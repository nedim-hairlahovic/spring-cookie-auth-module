package dev.nhairlahovic.auth.util;

import dev.nhairlahovic.auth.config.CookieConfigProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
@RequiredArgsConstructor
public class CookieUtilService {

    private final CookieConfigProperties cookieConfig;

    public String generateCookieValue(String user) {
        long authenticatedAt = System.currentTimeMillis();
        String valueToSign = user + "." + authenticatedAt;
        String hmac = HmacUtil.generateHmac(valueToSign, cookieConfig.getSecretKey());
        String cookieValue = valueToSign + "." + hmac;

        return Base64.getUrlEncoder().withoutPadding().encodeToString(cookieValue.getBytes());
    }

    public ResponseCookie createAuthCookie(String cookieValue) {
        return ResponseCookie
                .from(cookieConfig.getName(), cookieValue)
                .secure(cookieConfig.isSecure())
                .httpOnly(cookieConfig.isHttpOnly())
                .path(cookieConfig.getPath())
                .maxAge(cookieConfig.getMaxAge())
                .sameSite(cookieConfig.getSameSite())
                .build();
    }

    public ResponseCookie createExpiredAuthCookie() {
        return ResponseCookie
                .from(cookieConfig.getName(), "")
                .secure(cookieConfig.isSecure())
                .httpOnly(cookieConfig.isHttpOnly())
                .path(cookieConfig.getPath())
                .maxAge(0) // Instruct browser to delete the cookie
                .sameSite(cookieConfig.getSameSite())
                .build();
    }
}
