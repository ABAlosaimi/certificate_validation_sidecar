package github.certvalidator.certvalidator;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end mTLS integration test.
 *
 * Architecture:
 *   - Spring Boot starts a real HTTPS/Tomcat server on a random port.
 *   - Tomcat handles TLS termination + chain/signature verification (Tier-2).
 *   - CertValidationFilter reads the client cert from the request and runs
 *     all Tier-1 checks (self-signed, SAN, KU, EKU, temporal).
 *   - Both server and CA certs are generated in-memory by Bouncy Castle so
 *     no files need to be committed to the repo.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.allow-bean-definition-overriding=true",
        "cert.san.allow=client.internal"
    }
)
class MtlsIntegrationTest {

    private static final String KS_PW = "test";

    // Set by @DynamicPropertySource before context load; used in test methods.
    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static Path truststorePath;

    @LocalServerPort
    private int port;

    // Override keyManager — no real p12 file needed for the integration test.
    @TestConfiguration
    static class TestOverrides {
        @Bean
        @Primary
        public KeyManager[] keyManager() {
            return new KeyManager[0];
        }
    }

    // Generates the test PKI and configures Tomcat's SSL before the context starts.
    @DynamicPropertySource
    static void configureSsl(DynamicPropertyRegistry registry) {
        try {
            // CA — must have BasicConstraints(cA=true) so Java 21's PKIX validator
            // accepts it as a trust anchor.
            caKeyPair = newKeyPair();
            caCert = buildCaCert(caKeyPair);

            // Server cert signed by test CA
            KeyPair serverKP = newKeyPair();
            X509Certificate serverCert = buildCert(
                new X500Name("CN=localhost"), new X500Name("CN=Test CA"),
                serverKP, caKeyPair,
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(365, ChronoUnit.DAYS),
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")),
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment),
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
            );

            // Server keystore (PKCS12)
            Path serverKs = Files.createTempFile("server-ks-", ".p12");
            serverKs.toFile().deleteOnExit();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("server", serverKP.getPrivate(), KS_PW.toCharArray(),
                new Certificate[]{serverCert, caCert});
            try (OutputStream out = Files.newOutputStream(serverKs)) {
                ks.store(out, KS_PW.toCharArray());
            }

            // Truststore — set as a static field so testTrustStoreCustomizer can read it
            truststorePath = Files.createTempFile("truststore-", ".p12");
            truststorePath.toFile().deleteOnExit();
            KeyStore ts = KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            ts.setCertificateEntry("ca", caCert);
            try (OutputStream out = Files.newOutputStream(truststorePath)) {
                ts.store(out, KS_PW.toCharArray());
            }

            // Spring Boot 4.x SSL Bundle API — replaces deprecated server.ssl.key-store /
            // server.ssl.trust-store flat properties.
            String ksUri  = "file:" + serverKs.toAbsolutePath();
            String tsUri  = "file:" + truststorePath.toAbsolutePath();

            registry.add("spring.ssl.bundle.jks.mtls-test.keystore.location",   () -> ksUri);
            registry.add("spring.ssl.bundle.jks.mtls-test.keystore.password",   () -> KS_PW);
            registry.add("spring.ssl.bundle.jks.mtls-test.keystore.type",       () -> "PKCS12");
            registry.add("spring.ssl.bundle.jks.mtls-test.truststore.location", () -> tsUri);
            registry.add("spring.ssl.bundle.jks.mtls-test.truststore.password", () -> KS_PW);
            registry.add("spring.ssl.bundle.jks.mtls-test.truststore.type",     () -> "PKCS12");
            registry.add("server.ssl.bundle",       () -> "mtls-test");
            registry.add("server.ssl.client-auth",  () -> "need");
            registry.add("server.ssl.enabled",      () -> "true");

        } catch (Exception e) {
            throw new RuntimeException("Test PKI setup failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void valid_client_cert_gets_200() throws Exception {
        KeyPair kp = newKeyPair();
        assertEquals(200, get("/api/hello", clientCtx(kp, validClientCert(kp))));
    }

    @Test
    void cert_with_wrong_san_gets_403() throws Exception {
        // Signed by trusted CA (passes Tomcat TLS), but SAN not in allow-list
        KeyPair kp = newKeyPair();
        X509Certificate cert = buildCert(
            new X500Name("CN=rogue"), new X500Name("CN=Test CA"),
            kp, caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.DAYS),
            new GeneralNames(new GeneralName(GeneralName.dNSName, "rogue.example.com")),
            new KeyUsage(KeyUsage.digitalSignature),
            new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)
        );
        assertEquals(403, get("/api/hello", clientCtx(kp, cert)));
    }

    @Test
    void cert_with_wrong_eku_rejected_at_tls_layer() throws Exception {
        // Java 21's JSSE enforces id-kp-clientAuth EKU for client certificates, so a
        // cert carrying only serverAuth is rejected during the TLS handshake itself (-1),
        // before the request ever reaches our filter. The filter's EKU check therefore
        // acts as defense-in-depth for configurations that bypass JSSE's own enforcement.
        KeyPair kp = newKeyPair();
        X509Certificate cert = buildCert(
            new X500Name("CN=client.internal"), new X500Name("CN=Test CA"),
            kp, caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.DAYS),
            new GeneralNames(new GeneralName(GeneralName.dNSName, "client.internal")),
            new KeyUsage(KeyUsage.digitalSignature),
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
        );
        assertEquals(-1, get("/api/hello", clientCtx(kp, cert)));
    }

    @Test
    void cert_with_no_ku_gets_403() throws Exception {
        KeyPair kp = newKeyPair();
        X509Certificate cert = buildCert(
            new X500Name("CN=client.internal"), new X500Name("CN=Test CA"),
            kp, caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.DAYS),
            new GeneralNames(new GeneralName(GeneralName.dNSName, "client.internal")),
            null, // no KU extension
            new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)
        );
        assertEquals(403, get("/api/hello", clientCtx(kp, cert)));
    }

    @Test
    void expired_cert_is_rejected_at_tls_layer() throws Exception {
        // Tomcat/JSSE rejects expired client certs during PKIX validation
        KeyPair kp = newKeyPair();
        X509Certificate cert = buildCert(
            new X500Name("CN=client.internal"), new X500Name("CN=Test CA"),
            kp, caKeyPair,
            Instant.now().minus(10, ChronoUnit.DAYS),
            Instant.now().minus(1, ChronoUnit.DAYS),  // expired yesterday
            new GeneralNames(new GeneralName(GeneralName.dNSName, "client.internal")),
            new KeyUsage(KeyUsage.digitalSignature),
            new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)
        );
        assertEquals(-1, get("/api/hello", clientCtx(kp, cert)));
    }

    @Test
    void untrusted_self_signed_cert_is_rejected_at_tls_layer() throws Exception {
        // Server truststore only has our test CA; a self-signed cert is unknown → SSL alert
        KeyPair kp = newKeyPair();
        X509Certificate selfSigned = buildCert(
            new X500Name("CN=client.internal"), new X500Name("CN=client.internal"),
            kp, kp,  // signed by itself, NOT by our CA
            Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.DAYS),
            new GeneralNames(new GeneralName(GeneralName.dNSName, "client.internal")),
            new KeyUsage(KeyUsage.digitalSignature),
            new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)
        );

        // Build client context: presents self-signed cert, trusts server via CA
        KeyStore clientKs = KeyStore.getInstance("PKCS12");
        clientKs.load(null, null);
        clientKs.setKeyEntry("client", kp.getPrivate(), KS_PW.toCharArray(),
            new Certificate[]{selfSigned});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(clientKs, KS_PW.toCharArray());

        KeyStore clientTs = KeyStore.getInstance("PKCS12");
        clientTs.load(null, null);
        clientTs.setCertificateEntry("ca", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(clientTs);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        assertEquals(-1, get("/api/hello", ctx));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private X509Certificate validClientCert(KeyPair kp) throws Exception {
        return buildCert(
            new X500Name("CN=client.internal"), new X500Name("CN=Test CA"),
            kp, caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.DAYS),
            new GeneralNames(new GeneralName(GeneralName.dNSName, "client.internal")),
            new KeyUsage(KeyUsage.digitalSignature),
            new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)
        );
    }

    private SSLContext clientCtx(KeyPair kp, X509Certificate cert) throws Exception {
        // Client keystore: client cert chain
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", kp.getPrivate(), KS_PW.toCharArray(),
            new Certificate[]{cert, caCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, KS_PW.toCharArray());

        // Client truststore: trusts the server via the test CA
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    /** Make a GET request; returns HTTP status or -1 on SSL handshake failure. */
    private int get(String path, SSLContext sslContext) {
        HttpsURLConnection conn = null;
        try {
            URL url = new URL("https://localhost:" + port + path);
            conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.setHostnameVerifier((hostname, session) -> true);
            return conn.getResponseCode();
        } catch (SSLHandshakeException e) {
            return -1;
        } catch (IOException e) {
            return -1;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    /** Builds a self-signed CA cert with BasicConstraints(cA=true) and keyCertSign KU. */
    private static X509Certificate buildCaCert(KeyPair kp) throws Exception {
        X500Name ca = new X500Name("CN=Test CA");
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
            ca, BigInteger.valueOf(System.nanoTime()),
            Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
            Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
            ca, kp.getPublic()
        );
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(signer));
    }

    private static X509Certificate buildCert(
        X500Name subject, X500Name issuer,
        KeyPair subjectKP, KeyPair issuerKP,
        Instant notBefore, Instant notAfter,
        GeneralNames san, KeyUsage ku, ExtendedKeyUsage eku
    ) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer, BigInteger.valueOf(System.nanoTime()),
            Date.from(notBefore), Date.from(notAfter),
            subject, subjectKP.getPublic()
        );
        if (san != null) builder.addExtension(Extension.subjectAlternativeName, false, san);
        if (ku  != null) builder.addExtension(Extension.keyUsage, true, ku);
        if (eku != null) builder.addExtension(Extension.extendedKeyUsage, false, eku);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .build(issuerKP.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
