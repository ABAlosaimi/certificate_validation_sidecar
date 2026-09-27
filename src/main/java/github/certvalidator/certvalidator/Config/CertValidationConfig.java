package github.certvalidator.certvalidator.Config;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CertValidationConfig {

    // these should be env vars on sys level too so they are not included in the jar
    @Value("${keys.default.keymanager.password}")
    private String keyManagerPw;
    @Value("${keys.default.keymanager.container.format}")
    private String keyManagerKeyStoreInstanceFormat;
    @Value("${cert.san.allow}")
    private List<String> sanAllowList;

    String p12Path = System.getenv("APP_IDENTITY_PATH");                                                                                                                                                                                                                
    String p12Password = System.getenv("APP_IDENTITY_PASSWORD");   

    // The SSL (TLS) Context and engine start (javax)
    @Bean
    public SSLContext sslContext() throws NoSuchAlgorithmException {
        return SSLContext.getInstance("TLS");
    }

    @Bean
    public KeyManager[] keyManager() throws Exception {
        char[] password = keyManagerPw.toCharArray();
        KeyStore ks = KeyStore.getInstance(keyManagerKeyStoreInstanceFormat);

        ks.load(new FileInputStream(p12Path), p12Password.toCharArray()); 
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        kmf.init(ks, password);
        KeyManager[] keyManagers = kmf.getKeyManagers();

        return keyManagers;
    }
    // The SSL (TLS) Context and engine end (javax)

    // SANs allow list config start
    @Bean
    public List<String> sanAllow() {
        return this.sanAllowList;
    }
    // SANs allow list config end
}