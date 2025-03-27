# spring-cookie-auth-module

A reusable Spring Boot module for secure cookie-based authentication.

## Features
- Cookie-based authentication using **HTTP-only** and **Secure** cookies.
- Stateless authentication (no session storage required).
- HMAC signing for cookie validation.
- Custom authentication filter, provider and configurer for Spring Security.

## Git Submodule Integration

This module is designed to be used as a **Git submodule** in your main project.  
To add it as a submodule, run:

```sh
git submodule add https://github.com/nedim-hairlahovic/spring-cookie-auth-module.git <folder-name>
git submodule update --init --recursive
```

After adding, include it in your main project's  `pom.xml`:
```xml
<dependency>
    <groupId>dev.nhairlahovic</groupId>
    <artifactId>spring-cookie-auth</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```
## Configuration

Add these properties to `application.properties`:
```properties
cookie.auth.secret-key=your-secure-key # required
cookie.auth.max-age=86400  # Cookie expiration in seconds (1 day) - optional
cookie.auth.same-site=Strict # optional
```

## Usage

### Enable Security Configuration

Ensure your `SecurityConfig` includes `CookieAuthenticationConfigurer`:
```java
public class SecurityConfig {

    private final CookieAuthenticationProvider cookieAuthenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                ... other configurations
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/public", "/api/auth").permitAll();
                    auth.anyRequest().authenticated();
                })
                .with(new CookieAuthenticationConfigurer(cookieAuthenticationProvider), withDefaults())
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling.authenticationEntryPoint(new DefaultAuthenticationEntryPoint()) // Add default exception for unauthorized requests
                )
                .build();
    }

    ...
```

### Authentication Example

Your login controller should issue an authentication cookie:
```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final CookieUtilService cookieUtilService;

    @PostMapping
    public AuthResponseDto login(@RequestBody AuthRequestDto authRequest,
                                 HttpServletResponse response) {
        CookieAuthenticationToken authResult = authService.authenticate(authRequest);
        ResponseCookie cookie = cookieUtilService.createAuthCookie(authResult.getCookie());
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return new AuthResponseDto(authResult.getName());
    }
}
```

This simple authentication service handles user login by verifying credentials, generating a secure authentication cookie, and returning a token for further authorization:
```java
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final CookieUtilService cookieService;

    public CookieAuthenticationToken authenticate(AuthRequestDto authRequestDto) {
        var authRequest = new UsernamePasswordAuthenticationToken(authRequestDto.username(), authRequestDto.password());
        Authentication authenticatedUser = authenticationManager.authenticate(authRequest);

        String cookie = cookieService.generateCookieValue(authenticatedUser.getName());

        return CookieAuthenticationToken.authenticated(authenticatedUser.getName(), cookie);
    }
}
```

## Example Implementation & Demo

For a complete example and a working demo project using this authentication module, check out [GitHub repo](https://github.com/nedim-hairlahovic/spring-cookie-auth-demo).
