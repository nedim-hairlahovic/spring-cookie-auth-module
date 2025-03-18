package dev.nhairlahovic.auth.config;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;

public class CookieAuthenticationToken extends AbstractAuthenticationToken {

    private final String username;
    @Getter
    private final String cookie;

    private CookieAuthenticationToken(String username, String cookie, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.username = username;
        this.cookie = cookie;
    }

    public static CookieAuthenticationToken authenticated(String username, String cookie) {
        var token = new CookieAuthenticationToken(username, cookie, AuthorityUtils.NO_AUTHORITIES);
        token.setAuthenticated(true);
        return token;
    }

    public static CookieAuthenticationToken unauthenticated(String cookie) {
        var token = new CookieAuthenticationToken(null, cookie, AuthorityUtils.NO_AUTHORITIES);
        token.setAuthenticated(false);
        return token;
    }

    @Override
    public Object getCredentials() {
        return cookie;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

}
