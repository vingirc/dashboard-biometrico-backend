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
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final String PIN_PATTERN = "\\d{4,6}";
    private static final int MIN_PASSWORD_LENGTH = 8;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;

    public List<UserResponse> listUsers() {
        return userRepository.findAll().stream().map(this::toResponse).toList();
    }

    public UserResponse createUser(CreateUserRequest request, Authentication authentication) {
        requireUsername(request.username());
        boolean hasPassword = request.password() != null && !request.password().isBlank();
        boolean hasPin = request.pin() != null && !request.pin().isBlank();
        if (!hasPassword && !hasPin) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El usuario debe tener al menos una credencial (password o pin)");
        }
        if (hasPassword && request.password().length() < MIN_PASSWORD_LENGTH) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El password debe tener al menos 8 caracteres");
        }
        if (hasPin) {
            requireValidPin(request.pin());
        }
        if (userRepository.existsByUsername(request.username())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El username ya existe");
        }

        User user = User.builder()
                .username(request.username())
                .password(hasPassword ? passwordEncoder.encode(request.password()) : null)
                .pin(hasPin ? passwordEncoder.encode(request.pin()) : null)
                .role(request.role() != null ? request.role() : Role.USER)
                .isEnabled(true)
                .failedLoginAttempts(0)
                .build();

        User saved = userRepository.save(user);
        audit(AuditEventType.USER_CREATED, authentication, saved, "role=" + saved.getRole());
        return toResponse(saved);
    }

    public UserResponse updateUser(UUID id, UpdateUserRequest request, Authentication authentication) {
        requireUsername(request.username());
        User user = findUser(id);
        if (userRepository.existsByUsernameAndIdNot(request.username(), id)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "El username ya existe");
        }

        String previousUsername = user.getUsername();
        user.setUsername(request.username());
        User saved = userRepository.save(user);
        audit(AuditEventType.USER_UPDATED, authentication, saved, "username: " + previousUsername + " -> " + saved.getUsername());
        return toResponse(saved);
    }

    public UserResponse changeRole(UUID id, ChangeRoleRequest request, Authentication authentication) {
        if (request.role() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "role es requerido");
        }
        User user = findUser(id);

        Role previousRole = user.getRole();
        user.setRole(request.role());
        User saved = userRepository.save(user);
        audit(AuditEventType.USER_ROLE_CHANGED, authentication, saved, "role: " + previousRole + " -> " + saved.getRole());
        return toResponse(saved);
    }

    public UserResponse resetPin(UUID id, ResetPinRequest request, Authentication authentication) {
        requireValidPin(request.pin());
        User user = findUser(id);

        user.setPin(passwordEncoder.encode(request.pin()));
        // Reponer el PIN tambien limpia el bloqueo por fuerza bruta: si no, el usuario seguiria
        // sin poder entrar con su credencial nueva hasta que expire lockedUntil.
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        User saved = userRepository.save(user);
        audit(AuditEventType.USER_PIN_RESET, authentication, saved, null);
        return toResponse(saved);
    }

    public UserResponse disableUser(UUID id, Authentication authentication) {
        return setEnabled(id, false, authentication);
    }

    public UserResponse enableUser(UUID id, Authentication authentication) {
        return setEnabled(id, true, authentication);
    }

    private UserResponse setEnabled(UUID id, boolean enabled, Authentication authentication) {
        User user = findUser(id);
        user.setIsEnabled(enabled);
        if (enabled) {
            // Rehabilitar tambien limpia cualquier bloqueo por fuerza bruta pendiente.
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
        }
        User saved = userRepository.save(user);
        audit(enabled ? AuditEventType.USER_ENABLED : AuditEventType.USER_DISABLED, authentication, saved, null);
        return toResponse(saved);
    }

    private User findUser(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));
    }

    private void requireUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "username es requerido");
        }
    }

    private void requireValidPin(String pin) {
        if (pin == null || !pin.matches(PIN_PATTERN)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El pin debe tener entre 4 y 6 digitos numericos");
        }
    }

    private void audit(AuditEventType eventType, Authentication authentication, User target, String detail) {
        auditLogService.record(eventType, authentication.getName(), target.getUsername(), null, detail);
    }

    private UserResponse toResponse(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getRole(), user.getIsEnabled());
    }
}
