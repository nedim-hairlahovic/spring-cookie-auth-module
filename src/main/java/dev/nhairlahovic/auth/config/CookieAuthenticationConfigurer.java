package dev.nhairlahovic.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CookieAuthenticationConfigurer extends AbstractHttpConfigurer<CookieAuthenticationConfigurer, HttpSecurity> {

    private final CookieAuthenticationProvider cookieAuthenticationProvider;
    private final CookieConfigProperties cookieConfig;

    @Override
    public void init(HttpSecurity http) {
        http.authenticationProvider(cookieAuthenticationProvider);
    }

    @Override
    public void configure(HttpSecurity http) {
        var authManager = http.getSharedObject(AuthenticationManager.class);
        var cookieAuthenticationFilter = new CookieAuthenticationFilter(authManager, cookieConfig);
        http.addFilterBefore(cookieAuthenticationFilter, AuthorizationFilter.class);
    }
}
