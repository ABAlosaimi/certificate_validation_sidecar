# certvalidator

A Spring Boot 4.x mTLS certificate-validation sidecar. It terminates TLS, enforces a strict allow-list of client certificate attributes, and forwards only validated requests to the upstream application.

---

## Architecture

The sidecar implements a two-tier validation split to keep expensive cryptographic work out of the hot path.

```
Client ──TLS handshake──► Tomcat (Tier-2) ──► CertValidationFilter (Tier-1) ──► Application
```

### Tier-2 — Tomcat / JSSE (transport layer)

Tomcat handles everything that requires cryptographic computation:

- Signature verification of the certificate chain
- Chain building against the configured trust anchors
- PKIX path validation
- Expired certificate rejection
- EKU enforcement (`id-kp-clientAuth` required by Java 21's JSSE)
- Untrusted / self-signed root rejection

If Tier-2 rejects a connection, the TLS handshake fails and the client receives an SSL alert — the request never reaches the application.

### Tier-1 — `CertValidationFilter` (application layer)

After TLS is established, the filter reads the client certificate from the `jakarta.servlet.request.X509Certificate` request attribute and runs cheap metadata-only checks via `CertValidationService`:

| Check | Method | Rejection code |
|-------|--------|----------------|
| Self-signed pre-filter | `Subject == Issuer` principal comparison | `SELF_SIGNED_CERTIFICATE` |
| SAN allow-list | Any DNS/IP SAN in `cert.san.allow` | `NO_SAN` / `INVALID_SAN` |
| Key Usage | Bit 0 (`digitalSignature`) must be set | `NO_KEY_USAGE` / `KEY_USAGE_NO_DIGITAL_SIGNATURE` |
| Extended Key Usage | OID `1.3.6.1.5.5.7.3.2` (`id-kp-clientAuth`) | `EKU_NOT_CLIENT_AUTH` |
| Temporal validity | `X509Certificate.checkValidity()` | Standard PKIX exception |

A Tier-1 rejection returns **HTTP 403 Forbidden**. A missing certificate returns **HTTP 401 Unauthorized**.

---

## Project Structure

```
src/
  main/
    java/.../certvalidator/
      CertvalidatorApplication.java       # Spring Boot entry point
      Config/
        CertValidationConfig.java         # SSLContext, KeyManager, SAN allow-list beans
      Services/
        CertValidationService.java        # Tier-1 validation logic
      Filter/
        CertValidationFilter.java         # OncePerRequestFilter — reads cert, calls service
      Controller/
        HelloController.java              # GET /api/hello — test endpoint
      Exceptions/
        InvalidCertificateException.java  # Typed CertificateException subclass
        GlobalExceptionHandler.java       # @RestControllerAdvice error handling
    resources/
      application.properties
  test/
    java/.../certvalidator/
      CertValidationServiceTest.java      # 11 unit tests — no Spring context
      MtlsIntegrationTest.java            # 6 end-to-end tests — real TLS + Tomcat
      CertvalidatorApplicationTests.java  # Context-load smoke test
```

---

## Configuration

All configuration is supplied via environment variables.

| Environment variable | Property | Description | Default |
|---------------------|----------|-------------|---------|
| `APP_KEYMANAGER_PW` | `keys.default.keymanager.password` | Password for the sidecar's identity keystore | `changeit` |
| `APP_KEYMANAGER_KEYSTORE_FORMAT` | `keys.default.keymanager.container.format` | Keystore format (`PKCS12`, `JKS`) | `PKCS12` |
| `APP_CERT_SAN_ALLOW` | `cert.san.allow` | Comma-separated DNS names or IP addresses the sidecar accepts as valid client SANs | _(required)_ |

### Identity keystore

Place the sidecar's own TLS certificate and private key in a PKCS12 file named `sidecar-identity.p12` in the working directory (or configure the path to match). The keystore password must match `APP_KEYMANAGER_PW`.

### Tomcat TLS (Spring Boot 4.x SSL Bundle API)

Configure Tomcat's keystore and truststore via the SSL Bundle API in `application.properties` (or as environment overrides):

```properties
spring.ssl.bundle.jks.<bundle-name>.keystore.location=file:/path/to/server.p12
spring.ssl.bundle.jks.<bundle-name>.keystore.password=<password>
spring.ssl.bundle.jks.<bundle-name>.keystore.type=PKCS12
spring.ssl.bundle.jks.<bundle-name>.truststore.location=file:/path/to/truststore.p12
spring.ssl.bundle.jks.<bundle-name>.truststore.password=<password>
spring.ssl.bundle.jks.<bundle-name>.truststore.type=PKCS12
server.ssl.bundle=<bundle-name>
server.ssl.client-auth=need
server.ssl.enabled=true
```

> Note: the flat `server.ssl.key-store` / `server.ssl.trust-store` properties are deprecated in Spring Boot 4.x. Use the SSL Bundle API shown above.

---

## Running

```bash
export APP_CERT_SAN_ALLOW=client.internal,10.0.0.1
export APP_KEYMANAGER_PW=changeit
./mvnw spring-boot:run
```

---

## Testing

### Unit tests (`CertValidationServiceTest`)

Tests `CertValidationService.validateCertificate()` in isolation — no Spring context, no network. Bouncy Castle generates RSA 2048 certificates in memory. There is one test per validation rule, each injecting exactly one violation.

```bash
./mvnw test -Dtest=CertValidationServiceTest \
  -DAPP_CERT_SAN_ALLOW=client.internal \
  -DAPP_KEYMANAGER_PW=changeit \
  -DAPP_KEYMANAGER_KEYSTORE_FORMAT=PKCS12
```

### Integration tests (`MtlsIntegrationTest`)

Starts a real Tomcat server on a random port with a dynamically generated in-memory PKI (CA + server cert). Six tests exercise the full TLS handshake plus the filter:

| Test | Expected result | Rejected by |
|------|----------------|-------------|
| Valid client cert | 200 | — |
| Wrong SAN | 403 | `CertValidationFilter` |
| No KU extension | 403 | `CertValidationFilter` |
| Wrong EKU (`serverAuth` only) | -1 (SSL alert) | Tomcat / Java 21 JSSE |
| Expired cert | -1 (SSL alert) | Tomcat / PKIX |
| Untrusted self-signed cert | -1 (SSL alert) | Tomcat / PKIX |

```bash
./mvnw test -Dtest=MtlsIntegrationTest \
  -DAPP_KEYMANAGER_PW=changeit \
  -DAPP_KEYMANAGER_KEYSTORE_FORMAT=PKCS12
```

### All tests

```bash
./mvnw test \
  -DAPP_CERT_SAN_ALLOW=client.internal \
  -DAPP_KEYMANAGER_PW=changeit \
  -DAPP_KEYMANAGER_KEYSTORE_FORMAT=PKCS12
```

---

## Design decisions

**Why not validate the chain in the sidecar?**
Chain building (`CertPathValidator`) requires loading trust anchors, resolving intermediate CAs, and potentially fetching CRL/OCSP. That is expensive and duplicates work that the TLS stack already does. The sidecar delegates all cryptographic validation to Tomcat/JSSE and focuses only on policy enforcement (SAN, KU, EKU).

**Why `X509ExtendedTrustManager` over `X509TrustManager`?**
`X509ExtendedTrustManager` exposes the `SSLEngine` overload of `checkClientTrusted`. This is the correct hook point when the certificate is presented during a TLS handshake — the plain `X509TrustManager` interface receives no connection context and is therefore unsuitable for server-side client certificate inspection.

**Why does `cert_with_wrong_eku_rejected_at_tls_layer` return -1 instead of 403?**
Java 21's JSSE enforces `id-kp-clientAuth` EKU during the TLS handshake itself. A client certificate that carries only `serverAuth` is rejected before the request reaches the filter. The sidecar's EKU check therefore acts as defence-in-depth for TLS configurations that do not enforce this.

**Why `@DynamicPropertySource` instead of `@BeforeAll` in the integration test?**
Spring Boot starts Tomcat during application context creation. SSL properties must be registered before the context is loaded. `@DynamicPropertySource` runs at the right lifecycle point; `@BeforeAll` runs too late.

**Why does the CA cert in integration tests need `BasicConstraints(cA=true)`?**
Java 21's PKIX validator requires trust anchors to carry the CA basic constraint. Without it the handshake fails with `TrustAnchor ... is not a CA certificate`.

---

## Dependencies

| Dependency | Scope | Purpose |
|-----------|-------|---------|
| `spring-boot-starter-web` | compile | Embedded Tomcat, MVC |
| `spring-boot-starter-test` | test | JUnit 5, AssertJ, Mockito |
| `org.bouncycastle:bcpkix-jdk18on:1.80` | test | In-memory X.509 certificate generation |
