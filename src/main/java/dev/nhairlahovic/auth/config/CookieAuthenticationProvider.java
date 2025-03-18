package dev.nhairlahovic.auth.config;

import dev.nhairlahovic.auth.util.HmacUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
@RequiredArgsConstructor
public class CookieAuthenticationProvider implements AuthenticationProvider {

    private final CookieConfigProperties cookieConfig;

    @Override
    public Authentication authenticate(Authentication authenticationToken) throws AuthenticationException {
        var authRequest = (CookieAuthenticationToken) authenticationToken;
        String encodedCookie = (String) authRequest.getCredentials();
        String decodedCookie = new String(Base64.getUrlDecoder().decode(encodedCookie));

        if (!isCookieValid(decodedCookie)) {
            throw new BadCredentialsException("Invalid authentication cookie.");
        }

        String username = extractUsername(decodedCookie);
        return CookieAuthenticationToken.authenticated(username, encodedCookie);
    }

    private boolean isCookieValid(String cookieValue) {
        // Split the cookie format: username.timestamp.hmac
        String[] parts = cookieValue.split("\\.");
        if (parts.length != 3) {
            return false;
        }

        String payload = parts[0] + "." + parts[1]; // username + timestamp
        String providedHmac = parts[2];

        String expectedHmac = HmacUtil.generateHmac(payload, cookieConfig.getSecretKey());

        return providedHmac.equals(expectedHmac);
    }

    private String extractUsername(String decodedCookie) {
        String[] cookieParts = decodedCookie.split("\\.");
        if (cookieParts.length < 1) {
            throw new BadCredentialsException("Invalid authentication cookie.");
        }
        return cookieParts[0]; // Extract username from token
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CookieAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
