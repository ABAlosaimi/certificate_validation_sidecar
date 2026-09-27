package github.certvalidator.certvalidator.Services;

import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.springframework.stereotype.Service;
import github.certvalidator.certvalidator.Exceptions.InvalidCertificateException;

@Service 
public class CertValidationService {
    
    private SSLContext ctx;
    private KeyManager[] keyManagers;
    private List<String> sanAllowList;

    public  CertValidationService(PKIXParameters pkixParameters, CertPathValidator validator, SSLContext ctx, KeyManager[] keyManagers, CertificateFactory cf, List<String> sanAllowList) {
        this.ctx = ctx;
        this.keyManagers = keyManagers;
        this.sanAllowList = sanAllowList;
    }

    public void validateCertificate(X509Certificate[] chain) throws CertificateException, CertPathValidatorException, InvalidAlgorithmParameterException {
        
        X509Certificate leafCert = chain[0];
        
        // Self signing validation
        if (leafCert.getSubjectX500Principal().equals(leafCert.getIssuerX500Principal())) {
            throw new InvalidCertificateException("Invalid Certificate: SELF_SIGNED_CERTIFICATE");
        }

        // SANs validation
        Collection<List<?>> sans = leafCert.getSubjectAlternativeNames();
        boolean anyMatch = sans.stream()
                               .filter(e -> (Integer)e.get(0) == 2 || (Integer)e.get(0) == 7)                                                                                                                                        
                               .map(e -> (String)e.get(1))                                                                                                                                                                           
                               .anyMatch(sanAllowList::contains);

        if (!anyMatch) throw new CertificateException("Invalid Certificate: INVALID_SAN");   
        
        // EKU and KU validation (we use here the OID to validate if the key is can be used for client validation which technically named id-kp-clientAuth)
        boolean[] ku = leafCert.getKeyUsage();

        if (ku == null) {
            throw new InvalidCertificateException("Invalid Certificate: NO_KEY_USAGE");
        }

        if (ku != null && !ku[0]) {
            throw new InvalidCertificateException("Invalid Certificate: KEY_USAGE_NO_DIGITAL_SIGNATURE");
        }

        List<String> eku = leafCert.getExtendedKeyUsage();

        boolean clientAuth = eku != null && eku.contains("1.3.6.1.5.5.7.3.2"); // id-kp-clientAuth 
        if (!clientAuth) {
            throw new InvalidCertificateException("Invalid Certificate: EKU_NOT_CLIENT_AUTH");
        }

        // Temporal validation
        leafCert.checkValidity();

    }

    public void extractLeafCertificate() throws Exception {
        ctx.init(keyManagers, new TrustManager[] {
                 new X509ExtendedTrustManager() {
                                 @Override
                                 public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                                   try{
                                        validateCertificate(chain); 
                                        // should throws CertificateException to abort handshake if one of the conditions aren't met
                                      } catch (CertificateException e) { 
                                        throw new CertificateException("Invalid certificate:", e.getCause()); 
                                      } catch (CertPathValidatorException e) {
                                        throw new CertificateException("Invalid certificate:", e.getCause()); 
                                      } catch (InvalidAlgorithmParameterException e) {
                                        throw new CertificateException("Invalid certificate:", e.getCause()); 
                                      }      
                                 }

                                 @Override
                                 public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
                                 @Override
                                 public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {throw new CertificateException("This TrustManager only supports SSLEngine-based validation");}
                                 @Override
                                 public X509Certificate[] getAcceptedIssuers() {return new X509Certificate[0];}
                                 @Override
                                 public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {throw new CertificateException("This TrustManager only supports SSLEngine-based validation"); }
                                 @Override
                                 public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {throw new CertificateException("This TrustManager only supports SSLEngine-based validation"); }
                                 @Override
                                 public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {throw new CertificateException("This TrustManager only supports SSLEngine-based validation");}
                }
        }, null);

        SSLEngine engine = ctx.createSSLEngine();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(true);
    }

}