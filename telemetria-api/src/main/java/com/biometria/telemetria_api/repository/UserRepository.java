package com.biometria.telemetria_api.repository;

import com.biometria.telemetria_api.model.Role;
import com.biometria.telemetria_api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    // Para renombrar: el username debe ser unico entre *los demas* usuarios, si no, guardar
    // una cuenta con su propio nombre sin cambios daria un falso conflicto.
    boolean existsByUsernameAndIdNot(String username, UUID id);

    boolean existsByRole(Role role);
}
