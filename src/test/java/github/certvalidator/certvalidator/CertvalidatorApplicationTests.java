package github.certvalidator.certvalidator;

import javax.net.ssl.KeyManager;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
  "cert.san.allow=client.internal",
  "cert.redirect.url=https://upstream.internal/app",
  "spring.main.allow-bean-definition-overriding=true"
})           
class CertvalidatorApplicationTests {

	@TestConfiguration
	static class TestConfig {
		@Bean
		@Primary
		public KeyManager[] keyManager() {
			return new KeyManager[0];
		}
	}

	@Test
	void contextLoads() {
	}

}
