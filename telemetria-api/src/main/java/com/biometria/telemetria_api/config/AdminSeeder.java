package com.biometria.telemetria_api.config;

import com.biometria.telemetria_api.model.Role;
import com.biometria.telemetria_api.model.User;
import com.biometria.telemetria_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class AdminSeeder implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.admin.default-username}")
    private String defaultUsername;

    @Value("${app.admin.default-password}")
    private String defaultPassword;

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.existsByRole(Role.ADMIN)) {
            return;
        }
        User admin = User.builder()
                .username(defaultUsername)
                .password(passwordEncoder.encode(defaultPassword))
                .role(Role.ADMIN)
                .isEnabled(true)
                .failedLoginAttempts(0)
                .build();
        userRepository.save(admin);
        log.warn("Se creo un usuario ADMIN por defecto '{}'. Cambia su password despues del primer login.", defaultUsername);
    }
}
