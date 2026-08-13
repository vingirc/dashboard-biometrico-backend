package com.biometria.telemetria_api.service;

import com.biometria.telemetria_api.dto.AuthResponse;
import com.biometria.telemetria_api.dto.LoginPinRequest;
import com.biometria.telemetria_api.dto.LoginRequest;
import com.biometria.telemetria_api.model.Role;
import com.biometria.telemetria_api.model.User;
import com.biometria.telemetria_api.repository.UserRepository;
import com.biometria.telemetria_api.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final int MAX_ATTEMPTS = 3;
    private static final String USERNAME = "ana";
    private static final String RAW_PASSWORD = "password-correcta";
    private static final String HASHED_PASSWORD = "$2a$10$hash-de-password";
    private static final String RAW_PIN = "1234";
    private static final String HASHED_PIN = "$2a$10$hash-de-pin";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void configurarPoliticaDeBloqueo() {
        ReflectionTestUtils.setField(authService, "maxAttempts", MAX_ATTEMPTS);
        ReflectionTestUtils.setField(authService, "lockoutDurationMinutes", 15L);
    }

    @Test
    void loginConCredencialesValidasDevuelveTokenYReiniciaElContador() {
        User user = habilitado();
        user.setFailedLoginAttempts(2);
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(RAW_PASSWORD, HASHED_PASSWORD)).thenReturn(true);
        when(jwtService.generateToken(user)).thenReturn("jwt-de-prueba");
        when(jwtService.getExpirationMs()).thenReturn(3_600_000L);

        AuthResponse response = authService.login(new LoginRequest(USERNAME, RAW_PASSWORD));

        assertThat(response.token()).isEqualTo("jwt-de-prueba");
        assertThat(response.username()).isEqualTo(USERNAME);
        assertThat(response.role()).isEqualTo(Role.USER);

        User guardado = capturarUsuarioGuardado();
        assertThat(guardado.getFailedLoginAttempts()).isZero();
        assertThat(guardado.getLockedUntil()).isNull();
    }

    @Test
    void loginConPasswordIncorrectaDevuelve401YSumaUnIntentoFallido() {
        User user = habilitado();
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("mala", HASHED_PASSWORD)).thenReturn(false);

        ResponseStatusException error = capturarError(() -> authService.login(new LoginRequest(USERNAME, "mala")));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(capturarUsuarioGuardado().getFailedLoginAttempts()).isEqualTo(1);
    }

    // Anti-enumeracion: un atacante no debe poder distinguir "ese usuario no existe" de
    // "ese usuario existe pero la password esta mal". Ambos caminos deben producir exactamente
    // la misma respuesta, mismo status y mismo texto.
    @Test
    void usuarioInexistenteYPasswordIncorrectaSonIndistinguibles() {
        User user = habilitado();
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("mala", HASHED_PASSWORD)).thenReturn(false);
        when(userRepository.findByUsername("fantasma")).thenReturn(Optional.empty());

        ResponseStatusException passwordMala =
                capturarError(() -> authService.login(new LoginRequest(USERNAME, "mala")));
        ResponseStatusException usuarioInexistente =
                capturarError(() -> authService.login(new LoginRequest("fantasma", "lo-que-sea")));

        assertThat(usuarioInexistente.getStatusCode()).isEqualTo(passwordMala.getStatusCode());
        assertThat(usuarioInexistente.getReason()).isEqualTo(passwordMala.getReason());
    }

    @Test
    void cuentaDeshabilitadaDevuelve401SinRegistrarIntento() {
        User user = habilitado();
        user.setIsEnabled(false);
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        ResponseStatusException error =
                capturarError(() -> authService.login(new LoginRequest(USERNAME, RAW_PASSWORD)));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        // Corta antes de comparar la password: una cuenta apagada no debe poder usarse ni siquiera
        // para sondear si la credencial era correcta.
        verify(passwordEncoder, never()).matches(any(), any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void cuentaBloqueadaDevuelve401AunqueLaPasswordSeaCorrecta() {
        User user = habilitado();
        user.setLockedUntil(Instant.now().plus(10, ChronoUnit.MINUTES));
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        ResponseStatusException error =
                capturarError(() -> authService.login(new LoginRequest(USERNAME, RAW_PASSWORD)));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void unBloqueoYaVencidoNoImpideElLogin() {
        User user = habilitado();
        user.setFailedLoginAttempts(MAX_ATTEMPTS);
        user.setLockedUntil(Instant.now().minus(1, ChronoUnit.MINUTES));
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(RAW_PASSWORD, HASHED_PASSWORD)).thenReturn(true);
        when(jwtService.generateToken(user)).thenReturn("jwt-de-prueba");
        when(jwtService.getExpirationMs()).thenReturn(3_600_000L);

        AuthResponse response = authService.login(new LoginRequest(USERNAME, RAW_PASSWORD));

        assertThat(response.token()).isEqualTo("jwt-de-prueba");
        assertThat(capturarUsuarioGuardado().getLockedUntil()).isNull();
    }

    @Test
    void alAlcanzarElMaximoDeIntentosLaCuentaQuedaBloqueada() {
        User user = habilitado();
        user.setFailedLoginAttempts(MAX_ATTEMPTS - 1);
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("mala", HASHED_PASSWORD)).thenReturn(false);

        capturarError(() -> authService.login(new LoginRequest(USERNAME, "mala")));

        User guardado = capturarUsuarioGuardado();
        assertThat(guardado.getFailedLoginAttempts()).isEqualTo(MAX_ATTEMPTS);
        assertThat(guardado.getLockedUntil()).isAfter(Instant.now());
    }

    @Test
    void loginPinConPinValidoDevuelveToken() {
        User user = habilitado();
        user.setPin(HASHED_PIN);
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(RAW_PIN, HASHED_PIN)).thenReturn(true);
        when(jwtService.generateToken(user)).thenReturn("jwt-de-prueba");
        when(jwtService.getExpirationMs()).thenReturn(3_600_000L);

        AuthResponse response = authService.loginPin(new LoginPinRequest(USERNAME, RAW_PIN));

        assertThat(response.token()).isEqualTo("jwt-de-prueba");
        assertThat(capturarUsuarioGuardado().getFailedLoginAttempts()).isZero();
    }

    @Test
    void loginPinConPinIncorrectoDevuelve401YSumaUnIntentoFallido() {
        User user = habilitado();
        user.setPin(HASHED_PIN);
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("9999", HASHED_PIN)).thenReturn(false);

        ResponseStatusException error =
                capturarError(() -> authService.loginPin(new LoginPinRequest(USERNAME, "9999")));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(capturarUsuarioGuardado().getFailedLoginAttempts()).isEqualTo(1);
    }

    // Una cuenta solo-password no puede entrar por PIN: sin este corte, passwordEncoder.matches
    // recibiria un hash nulo.
    @Test
    void loginPinEnCuentaSinPinDevuelve401() {
        User user = habilitado();
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        ResponseStatusException error =
                capturarError(() -> authService.loginPin(new LoginPinRequest(USERNAME, RAW_PIN)));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void loginEnCuentaSoloPinDevuelve401() {
        User user = habilitado();
        user.setPassword(null);
        user.setPin(HASHED_PIN);
        when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(user));

        ResponseStatusException error =
                capturarError(() -> authService.login(new LoginRequest(USERNAME, RAW_PASSWORD)));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(passwordEncoder, never()).matches(any(), any());
    }

    private User habilitado() {
        return User.builder()
                .id(UUID.randomUUID())
                .username(USERNAME)
                .password(HASHED_PASSWORD)
                .role(Role.USER)
                .isEnabled(true)
                .failedLoginAttempts(0)
                .build();
    }

    private User capturarUsuarioGuardado() {
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        return captor.getValue();
    }

    private ResponseStatusException capturarError(Runnable accion) {
        return catchThrowableOfType(ResponseStatusException.class, accion::run);
    }
}
