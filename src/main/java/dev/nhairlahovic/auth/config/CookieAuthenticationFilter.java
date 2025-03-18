package dev.nhairlahovic.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

@RequiredArgsConstructor
public class CookieAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public static final String AUTH_COOKIE_NAME = "AUTH-COOKIE";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Optional<Cookie> authCookie = getCookie(request, AUTH_COOKIE_NAME);

        if (authCookie.isPresent()) {
            String authCookieValue = authCookie.get().getValue();

            CookieAuthenticationToken authRequest = CookieAuthenticationToken.unauthenticated(authCookieValue);
            Authentication authResult = authenticationManager.authenticate(authRequest);

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authResult);
            SecurityContextHolder.setContext(context);
        }

        filterChain.doFilter(request, response);
    }

    private Optional<Cookie> getCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(cookieName))
                    .findFirst();
        }
        return Optional.empty();
    }
}
