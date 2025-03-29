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

To enable cookie-based authentication, you must configure the following properties in your `application.properties` or `application.yml`.

These properties are loaded via the `CookieConfigProperties` class, and most have default values. You only need to override them if your use case differs.

**Required:**
```properties
# Secret key used to sign and verify authentication cookies (HMAC)
# MUST be a strong, securely generated string
cookie.auth.secret-key=your-secure-key
```

**Optional Properties (with Defaults):**
| Property                  | Default Value   | Description                                              |
|---------------------------|-----------------|----------------------------------------------------------|
| `cookie.auth.name`        | `AUTH_COOKIE`    | Name of the authentication cookie                        |
| `cookie.auth.path`        | `/`              | Path for which the cookie is valid                       |
| `cookie.auth.same-site`   | `Strict`         | SameSite policy (`Strict`, `Lax`, or `None`)             |
| `cookie.auth.http-only`   | `true`           | Prevents access to the cookie from JavaScript            |
| `cookie.auth.secure`      | `true`           | Ensures cookie is only sent over HTTPS                   |
| `cookie.auth.max-age`     | `86400` (1 day)  | Expiration time of the cookie in seconds                 |

**Example:**
```properties
cookie.auth.secret-key=VGhpcy1pczEtVmVyeS1TZWN1cmUtU2VjcmV0S2V5IQ==
cookie.auth.name=MY_AUTH_COOKIE
cookie.auth.max-age=604800 # 7 days
cookie.auth.same-site=Lax
cookie.auth.secure=true
```

> ⚠️ **Note**: `cookie.auth.secret-key` is required due to `@ConditionalOnProperty`.  
> If not defined, `CookieConfigProperties` will not be loaded, and any dependent beans will fail to initialize.

## Usage

### Enable Security Configuration

Ensure your `SecurityConfig` includes `CookieAuthenticationConfigurer`:
```java
public class SecurityConfig {

    private final CookieAuthenticationConfigurer cookieAuthenticationConfigurer;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                ... other configurations
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/public", "/api/auth").permitAll();
                    auth.anyRequest().authenticated();
                })
                .with(cookieAuthenticationConfigurer, withDefaults())
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

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        ResponseCookie expiredCookie = cookieUtilService.createExpiredAuthCookie();
        response.addHeader(HttpHeaders.SET_COOKIE, expiredCookie.toString());
        return ResponseEntity.ok().build();
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
