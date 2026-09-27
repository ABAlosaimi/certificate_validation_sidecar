package github.certvalidator.certvalidator.Filter;

import github.certvalidator.certvalidator.Services.CertValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CertValidationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CertValidationFilter.class);
    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private final CertValidationService certValidationService;

    public CertValidationFilter(CertValidationService certValidationService) {
        this.certValidationService = certValidationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        X509Certificate[] chain =
            (X509Certificate[]) request.getAttribute(CERT_ATTRIBUTE);

        if (chain == null || chain.length == 0) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                "Client certificate required");
            return;
        }

        try {
            certValidationService.validateCertificate(chain);
        } catch (CertificateException e) {
            log.warn("Client certificate rejected: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
            return;
        }

        filterChain.doFilter(request, response);
    }
}
