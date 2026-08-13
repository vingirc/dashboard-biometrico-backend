package com.biometria.telemetria_api.service;

import com.biometria.telemetria_api.dto.AuthResponse;
import com.biometria.telemetria_api.dto.LoginPinRequest;
import com.biometria.telemetria_api.dto.LoginRequest;
import com.biometria.telemetria_api.model.User;
import com.biometria.telemetria_api.repository.UserRepository;
import com.biometria.telemetria_api.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${app.security.lockout.max-attempts}")
    private int maxAttempts;

    @Value("${app.security.lockout.duration-minutes}")
    private long lockoutDurationMinutes;

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas"));

        assertUsable(user);

        if (user.getPassword() == null || !passwordEncoder.matches(request.password(), user.getPassword())) {
            registerFailedAttempt(user);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas");
        }

        registerSuccessfulLogin(user);
        return buildAuthResponse(user);
    }

    public AuthResponse loginPin(LoginPinRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas"));

        assertUsable(user);

        if (user.getPin() == null || !passwordEncoder.matches(request.pin(), user.getPin())) {
            registerFailedAttempt(user);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas");
        }

        registerSuccessfulLogin(user);
        return buildAuthResponse(user);
    }

    // Cuenta inexistente, deshabilitada, bloqueada por intentos fallidos o password/pin incorrecto
    // responden todas exactamente igual (401 generico) a proposito -- evita que alguien enumere que
    // usernames existen o en que estado estan probando logins sin saber ninguna contraseña real.
    // La logica de bloqueo (contar intentos, fijar lockedUntil) sigue funcionando igual por dentro,
    // solo cambia lo que se expone hacia afuera.
    private void assertUsable(User user) {
        boolean locked = user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now());
        if (locked || !Boolean.TRUE.equals(user.getIsEnabled())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales invalidas");
        }
    }

    private void registerFailedAttempt(User user) {
        int attempts = user.getFailedLoginAttempts() == null ? 1 : user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        if (attempts >= maxAttempts) {
            user.setLockedUntil(Instant.now().plus(lockoutDurationMinutes, ChronoUnit.MINUTES));
        }
        userRepository.save(user);
    }

    private void registerSuccessfulLogin(User user) {
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
    }

    private AuthResponse buildAuthResponse(User user) {
        String token = jwtService.generateToken(user);
        return new AuthResponse(token, user.getUsername(), user.getRole(), jwtService.getExpirationMs());
    }
}
