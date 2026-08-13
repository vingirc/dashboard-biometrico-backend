package com.biometria.telemetria_api.service;

import com.biometria.telemetria_api.dto.ChangeRoleRequest;
import com.biometria.telemetria_api.dto.CreateUserRequest;
import com.biometria.telemetria_api.dto.ResetPinRequest;
import com.biometria.telemetria_api.dto.UpdateUserRequest;
import com.biometria.telemetria_api.dto.UserResponse;
import com.biometria.telemetria_api.model.AuditEventType;
import com.biometria.telemetria_api.model.Role;
import com.biometria.telemetria_api.model.User;
import com.biometria.telemetria_api.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    private static final String ACTOR = "admin";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private UserService userService;

    // ---------- createUser ----------

    @Test
    void createUserGuardaElPasswordHasheadoYNuncaEnClaro() {
        when(authentication.getName()).thenReturn(ACTOR);
        when(userRepository.existsByUsername("ana")).thenReturn(false);
        when(passwordEncoder.encode("password-larga")).thenReturn("hash-password");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponse response = userService.createUser(
                new CreateUserRequest("ana", "password-larga", null, Role.USER), authentication);

        assertThat(response.username()).isEqualTo("ana");
        User guardado = capturarGuardado();
        assertThat(guardado.getPassword()).isEqualTo("hash-password");
        assertThat(guardado.getIsEnabled()).isTrue();
        verify(auditLogService).record(eq(AuditEventType.USER_CREATED), eq(ACTOR), eq("ana"), isNull(), any());
    }

    @Test
    void createUserSinRolAsignaUserPorDefecto() {
        when(authentication.getName()).thenReturn(ACTOR);
        when(userRepository.existsByUsername("ana")).thenReturn(false);
        when(passwordEncoder.encode("password-larga")).thenReturn("hash-password");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponse response = userService.createUser(
                new CreateUserRequest("ana", "password-larga", null, null), authentication);

        // Fail-closed: sin rol explicito se otorga el menos privilegiado, nunca ADMIN.
        assertThat(response.role()).isEqualTo(Role.USER);
    }

    @Test
    void createUserConUsernameEnBlancoDevuelve400() {
        assertThat(errorAlCrear(new CreateUserRequest("   ", "password-larga", null, null)))
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void createUserSinPasswordNiPinDevuelve400() {
        assertThat(errorAlCrear(new CreateUserRequest("ana", null, null, null)))
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void createUserConPasswordCortoDevuelve400() {
        assertThat(errorAlCrear(new CreateUserRequest("ana", "corta", null, null)))
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void createUserConPinNoNumericoDevuelve400() {
        assertThat(errorAlCrear(new CreateUserRequest("ana", null, "abcd", null)))
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void createUserConPinDemasiadoLargoDevuelve400() {
        assertThat(errorAlCrear(new CreateUserRequest("ana", null, "1234567", null)))
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void createUserConUsernameDuplicadoDevuelve409() {
        when(userRepository.existsByUsername("ana")).thenReturn(true);

        assertThat(errorAlCrear(new CreateUserRequest("ana", "password-larga", null, null)))
                .isEqualTo(HttpStatus.CONFLICT);
        verify(userRepository, never()).save(any());
    }

    @Test
    void createUserNoPersisteNadaCuandoLaValidacionFalla() {
        errorAlCrear(new CreateUserRequest("ana", "corta", null, null));

        verify(userRepository, never()).save(any());
        verify(auditLogService, never()).record(any(), any(), any(), any(), any());
    }

    // ---------- updateUser ----------

    @Test
    void updateUserRenombraYRegistraElCambio() {
        User user = existente("ana");
        when(authentication.getName()).thenReturn(ACTOR);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.existsByUsernameAndIdNot("ana2", user.getId())).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponse response = userService.updateUser(user.getId(), new UpdateUserRequest("ana2"), authentication);

        assertThat(response.username()).isEqualTo("ana2");
        verify(auditLogService).record(eq(AuditEventType.USER_UPDATED), eq(ACTOR), eq("ana2"), isNull(), any());
    }

    @Test
    void updateUserConUsernameDeOtraCuentaDevuelve409() {
        User user = existente("ana");
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.existsByUsernameAndIdNot("beto", user.getId())).thenReturn(true);

        ResponseStatusException error = capturarError(
                () -> userService.updateUser(user.getId(), new UpdateUserRequest("beto"), authentication));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        verify(userRepository, never()).save(any());
    }

    // Renombrarse a si mismo no es un conflicto: la consulta excluye el propio id.
    @Test
    void updateUserConSuPropioUsernameNoEsConflicto() {
        User user = existente("ana");
        when(authentication.getName()).thenReturn(ACTOR);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.existsByUsernameAndIdNot("ana", user.getId())).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponse response = userService.updateUser(user.getId(), new UpdateUserRequest("ana"), authentication);

        assertThat(response.username()).isEqualTo("ana");
    }

    @Test
    void updateUserConUsernameEnBlancoDevuelve400() {
        ResponseStatusException error = capturarError(
                () -> userService.updateUser(UUID.randomUUID(), new UpdateUserRequest(""), authentication));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(userRepository, never()).findById(any());
    }

    // ---------- changeRole ----------

    @Test
    void changeRoleActualizaElRolYRegistraElCambio() {
        User user = existente("ana");
        when(authentication.getName()).thenReturn(ACTOR);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponse response = userService.changeRole(user.getId(), new ChangeRoleRequest(Role.ADMIN), authentication);

        assertThat(response.role()).isEqualTo(Role.ADMIN);
        verify(auditLogService).record(eq(AuditEventType.USER_ROLE_CHANGED), eq(ACTOR), eq("ana"), isNull(), any());
    }

    @Test
    void changeRoleSobreUsuarioInexistenteDevuelve404() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.empty());

        ResponseStatusException error = capturarError(
                () -> userService.changeRole(id, new ChangeRoleRequest(Role.ADMIN), authentication));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void changeRoleSinRolDevuelve400() {
        ResponseStatusException error = capturarError(
                () -> userService.changeRole(UUID.randomUUID(), new ChangeRoleRequest(null), authentication));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(userRepository, never()).findById(any());
    }

    // ---------- resetPin ----------

    @Test
    void resetPinGuardaElHashNuncaElPinEnClaroYLevantaElBloqueo() {
        User user = existente("ana");
        user.setPin("hash-viejo");
        user.setFailedLoginAttempts(5);
        user.setLockedUntil(Instant.now().plus(10, ChronoUnit.MINUTES));
        when(authentication.getName()).thenReturn(ACTOR);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.encode("4321")).thenReturn("hash-nuevo");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        userService.resetPin(user.getId(), new ResetPinRequest("4321"), authentication);

        User guardado = capturarGuardado();
        assertThat(guardado.getPin()).isEqualTo("hash-nuevo");
        assertThat(guardado.getFailedLoginAttempts()).isZero();
        assertThat(guardado.getLockedUntil()).isNull();
        verify(auditLogService).record(eq(AuditEventType.USER_PIN_RESET), eq(ACTOR), eq("ana"), isNull(), isNull());
    }

    @Test
    void resetPinConFormatoInvalidoDevuelve400() {
        ResponseStatusException error = capturarError(
                () -> userService.resetPin(UUID.randomUUID(), new ResetPinRequest("12"), authentication));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(passwordEncoder, never()).encode(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void resetPinSinPinDevuelve400() {
        ResponseStatusException error = capturarError(
                () -> userService.resetPin(UUID.randomUUID(), new ResetPinRequest(null), authentication));

        assertThat(error.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    // ---------- enable / disable ----------

    @Test
    void enableUserLimpiaElBloqueoPorFuerzaBruta() {
        User user = existente("ana");
        user.setIsEnabled(false);
        user.setFailedLoginAttempts(5);
        user.setLockedUntil(Instant.now().plus(10, ChronoUnit.MINUTES));
        when(authentication.getName()).thenReturn(ACTOR);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        userService.enableUser(user.getId(), authentication);

        User guardado = capturarGuardado();
        assertThat(guardado.getIsEnabled()).isTrue();
        assertThat(guardado.getFailedLoginAttempts()).isZero();
        assertThat(guardado.getLockedUntil()).isNull();
        verify(auditLogService).record(eq(AuditEventType.USER_ENABLED), eq(ACTOR), eq("ana"), isNull(), isNull());
    }

    @Test
    void disableUserApagaLaCuentaYQuedaRegistrado() {
        User user = existente("ana");
        when(authentication.getName()).thenReturn(ACTOR);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        userService.disableUser(user.getId(), authentication);

        assertThat(capturarGuardado().getIsEnabled()).isFalse();
        verify(auditLogService).record(eq(AuditEventType.USER_DISABLED), eq(ACTOR), eq("ana"), isNull(), isNull());
    }

    @Test
    void disableUserSobreUsuarioInexistenteDevuelve404() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.empty());

        assertThat(capturarError(() -> userService.disableUser(id, authentication)).getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    private User existente(String username) {
        return User.builder()
                .id(UUID.randomUUID())
                .username(username)
                .password("hash-password")
                .role(Role.USER)
                .isEnabled(true)
                .failedLoginAttempts(0)
                .build();
    }

    private User capturarGuardado() {
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        return captor.getValue();
    }

    private HttpStatus errorAlCrear(CreateUserRequest request) {
        return HttpStatus.valueOf(
                capturarError(() -> userService.createUser(request, authentication)).getStatusCode().value());
    }

    private ResponseStatusException capturarError(Runnable accion) {
        return catchThrowableOfType(ResponseStatusException.class, accion::run);
    }
}
