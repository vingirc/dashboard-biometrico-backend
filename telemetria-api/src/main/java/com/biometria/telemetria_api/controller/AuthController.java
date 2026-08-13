package com.biometria.telemetria_api.controller;

import com.biometria.telemetria_api.dto.AuthResponse;
import com.biometria.telemetria_api.dto.LoginPinRequest;
import com.biometria.telemetria_api.dto.LoginRequest;
import com.biometria.telemetria_api.dto.SessionResponse;
import com.biometria.telemetria_api.model.AuditEventType;
import com.biometria.telemetria_api.model.Role;
import com.biometria.telemetria_api.security.JwtService;
import com.biometria.telemetria_api.security.LoginRateLimiter;
import com.biometria.telemetria_api.service.AuditLogService;
import com.biometria.telemetria_api.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.function.Supplier;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    public static final String COOKIE_NAME = "auth_token";

    private final AuthService authService;
    private final LoginRateLimiter loginRateLimiter;
    private final JwtService jwtService;
    private final AuditLogService auditLogService;

    @Value("${app.cookie.secure}")
    private boolean cookieSecure;

    @PostMapping("/login")
    public SessionResponse login(@RequestBody LoginRequest request, HttpServletRequest httpRequest,
                                  HttpServletResponse httpResponse) {
        checkRateLimit(httpRequest);
        AuthResponse auth = auditedLogin(() -> authService.login(request), request.username(), "password", httpRequest);
        setAuthCookie(httpResponse, auth.token());
        return new SessionResponse(auth.username(), auth.role());
    }

    @PostMapping("/login-pin")
    public SessionResponse loginPin(@RequestBody LoginPinRequest request, HttpServletRequest httpRequest,
                                     HttpServletResponse httpResponse) {
        checkRateLimit(httpRequest);
        AuthResponse auth = auditedLogin(() -> authService.loginPin(request), request.username(), "pin", httpRequest);
        setAuthCookie(httpResponse, auth.token());
        return new SessionResponse(auth.username(), auth.role());
    }

    // Devuelve la sesion actual a partir de la cookie httpOnly que ya valido JwtAuthFilter.
    // El frontend la usa para saber "quien soy" sin haber guardado nada el mismo en localStorage.
    @GetMapping("/me")
    public SessionResponse me() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        String role = authentication.getAuthorities().iterator().next().getAuthority().replace("ROLE_", "");
        return new SessionResponse(authentication.getName(), Role.valueOf(role));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse httpResponse) {
        clearAuthCookie(httpResponse);
        return ResponseEntity.noContent().build();
    }

    // Deja rastro de cada intento sin alterar lo que ve el cliente: la excepcion original se
    // vuelve a lanzar tal cual, asi que el 401 generico anti-enumeracion de AuthService se mantiene.
    // El motivo exacto del fallo no se registra -- distinguir "no existe" de "password mala" en la
    // bitacora no aporta al operador y filtraria la enumeracion a quien lea los logs.
    private AuthResponse auditedLogin(Supplier<AuthResponse> attempt, String attemptedUsername, String method,
                                      HttpServletRequest httpRequest) {
        String ip = httpRequest.getRemoteAddr();
        try {
            AuthResponse auth = attempt.get();
            auditLogService.record(AuditEventType.LOGIN_SUCCESS, auth.username(), auth.username(), ip, "metodo=" + method);
            return auth;
        } catch (ResponseStatusException e) {
            auditLogService.record(AuditEventType.LOGIN_FAILURE, null, attemptedUsername, ip, "metodo=" + method);
            throw e;
        }
    }

    private void checkRateLimit(HttpServletRequest httpRequest) {
        if (!loginRateLimiter.tryConsume(httpRequest.getRemoteAddr())) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Demasiados intentos de inicio de sesion desde esta direccion. Intenta de nuevo mas tarde.");
        }
    }

    private void setAuthCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, token)
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofMillis(jwtService.getExpirationMs()))
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void clearAuthCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
