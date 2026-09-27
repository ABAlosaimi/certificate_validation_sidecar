package github.certvalidator.certvalidator;

import github.certvalidator.certvalidator.Services.CertValidationService;
import org.bouncycastle.asn1.x500.X500Name;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class CertValidationServiceTest {

    private static final List<String> ALLOW_LIST = List.of("client.internal");
    private static KeyPair caKeyPair;
    private static X509Certificate caCert;

    private CertValidationService service;

    @BeforeAll
    static void generateCA() throws Exception {
        caKeyPair = newKeyPair();
        caCert = buildCert(
            new X500Name("CN=Test CA"),
            new X500Name("CN=Test CA"),
            caKeyPair, caKeyPair,
            Instant.now().minus(1, ChronoUnit.DAYS),
            Instant.now().plus(365, ChronoUnit.DAYS),
            null, null, null
        );
    }

    @BeforeEach
    void setUp() throws Exception {
        service = new CertValidationService(
            mock(SSLContext.class),
            new KeyManager[0],
            ALLOW_LIST
        );
    }

    // --- happy path ---

    @Test
    void accepts_valid_cert() throws Exception {
        X509Certificate leaf = validLeaf();
        assertDoesNotThrow(() -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
    }

    // --- self-signed filter ---

    @Test
    void rejects_self_signed_cert() throws Exception {
        KeyPair kp = newKeyPair();
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=client.internal"), // subject == issuer
            kp, kp,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            dns("client.internal"), ku(KeyUsage.digitalSignature), eku(KeyPurposeId.id_kp_clientAuth)
        );
        CertificateException ex = assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
        assertTrue(ex.getMessage().contains("SELF_SIGNED_CERTIFICATE"));
    }

    // --- SAN checks ---

    @Test
    void rejects_cert_with_no_san_extension() throws Exception {
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            null, // no SAN
            ku(KeyUsage.digitalSignature), eku(KeyPurposeId.id_kp_clientAuth)
        );
        CertificateException ex = assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
        assertTrue(ex.getMessage().contains("NO_SAN"));
    }

    @Test
    void rejects_cert_whose_san_is_not_in_allowlist() throws Exception {
        X509Certificate leaf = buildCert(
            new X500Name("CN=rogue.example.com"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            dns("rogue.example.com"),
            ku(KeyUsage.digitalSignature), eku(KeyPurposeId.id_kp_clientAuth)
        );
        CertificateException ex = assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
        assertTrue(ex.getMessage().contains("INVALID_SAN"));
    }

    @Test
    void accepts_cert_with_extra_san_as_long_as_one_matches() throws Exception {
        // cert has two DNS SANs: one in the allow-list, one not
        GeneralNames twoSans = new GeneralNames(new GeneralName[]{
            new GeneralName(GeneralName.dNSName, "client.internal"),
            new GeneralName(GeneralName.dNSName, "other.example.com")
        });
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            twoSans,
            ku(KeyUsage.digitalSignature), eku(KeyPurposeId.id_kp_clientAuth)
        );
        assertDoesNotThrow(() -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
    }

    // --- KU checks ---

    @Test
    void rejects_cert_with_no_ku_extension() throws Exception {
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            dns("client.internal"),
            null, // no KU
            eku(KeyPurposeId.id_kp_clientAuth)
        );
        CertificateException ex = assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
        assertTrue(ex.getMessage().contains("NO_KEY_USAGE"));
    }

    @Test
    void rejects_cert_without_digital_signature_bit() throws Exception {
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            dns("client.internal"),
            ku(KeyUsage.keyEncipherment), // bit 0 (digitalSignature) not set
            eku(KeyPurposeId.id_kp_clientAuth)
        );
        CertificateException ex = assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
        assertTrue(ex.getMessage().contains("KEY_USAGE_NO_DIGITAL_SIGNATURE"));
    }

    // --- EKU checks ---

    @Test
    void rejects_cert_with_no_eku_extension() throws Exception {
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            dns("client.internal"),
            ku(KeyUsage.digitalSignature),
            null // no EKU
        );
        CertificateException ex = assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
        assertTrue(ex.getMessage().contains("EKU_NOT_CLIENT_AUTH"));
    }

    @Test
    void rejects_cert_with_server_auth_eku_only() throws Exception {
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            dns("client.internal"),
            ku(KeyUsage.digitalSignature),
            eku(KeyPurposeId.id_kp_serverAuth) // serverAuth, not clientAuth
        );
        CertificateException ex = assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
        assertTrue(ex.getMessage().contains("EKU_NOT_CLIENT_AUTH"));
    }

    // --- temporal checks ---

    @Test
    void rejects_expired_cert() throws Exception {
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(10, ChronoUnit.DAYS),
            Instant.now().minus(1, ChronoUnit.DAYS), // expired yesterday
            dns("client.internal"),
            ku(KeyUsage.digitalSignature), eku(KeyPurposeId.id_kp_clientAuth)
        );
        assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
    }

    @Test
    void rejects_not_yet_valid_cert() throws Exception {
        X509Certificate leaf = buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().plus(1, ChronoUnit.DAYS),  // starts tomorrow
            Instant.now().plus(10, ChronoUnit.DAYS),
            dns("client.internal"),
            ku(KeyUsage.digitalSignature), eku(KeyPurposeId.id_kp_clientAuth)
        );
        assertThrows(CertificateException.class,
            () -> service.validateCertificate(new X509Certificate[]{leaf, caCert}));
    }

    // --- helpers ---

    private X509Certificate validLeaf() throws Exception {
        return buildCert(
            new X500Name("CN=client.internal"),
            new X500Name("CN=Test CA"),
            newKeyPair(), caKeyPair,
            Instant.now().minus(1, ChronoUnit.HOURS),
            Instant.now().plus(1, ChronoUnit.DAYS),
            dns("client.internal"),
            ku(KeyUsage.digitalSignature), eku(KeyPurposeId.id_kp_clientAuth)
        );
    }

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static GeneralNames dns(String name) {
        return new GeneralNames(new GeneralName(GeneralName.dNSName, name));
    }

    private static KeyUsage ku(int bits) {
        return new KeyUsage(bits);
    }

    private static ExtendedKeyUsage eku(KeyPurposeId... purposes) {
        return new ExtendedKeyUsage(purposes);
    }

    /**
     * Builds an X509Certificate with the given properties.
     * Pass null for san/ku/eku to omit that extension entirely.
     */
    private static X509Certificate buildCert(
        X500Name subject,
        X500Name issuer,
        KeyPair subjectKP,
        KeyPair issuerKP,
        Instant notBefore,
        Instant notAfter,
        GeneralNames san,
        KeyUsage ku,
        ExtendedKeyUsage eku
    ) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(notBefore),
            Date.from(notAfter),
            subject,
            subjectKP.getPublic()
        );
        if (san != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, san);
        }
        if (ku != null) {
            builder.addExtension(Extension.keyUsage, true, ku);
        }
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, eku);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKP.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
