package dev.nhairlahovic.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "cookie.auth")
@ConditionalOnProperty(prefix = "cookie.auth", name = "secret-key")
public class CookieConfigProperties {
    private String secretKey;
    private int maxAge = 86400; // Default: 1 day (86400 seconds)
    private String sameSite = "Strict";
}
