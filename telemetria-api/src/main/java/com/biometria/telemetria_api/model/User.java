package com.biometria.telemetria_api.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String username;

    // Hash BCrypt de la contraseña de login web. Nullable: una cuenta puede autenticarse solo por PIN.
    // @JsonIgnore es defensa en profundidad: la API nunca debe serializar esta entidad directamente (se usa UserResponse),
    // pero si algo la expusiera por error, el hash nunca debe llegar al cliente.
    @Column
    @JsonIgnore
    private String password;

    // Hash BCrypt del PIN de smartwatch (4-6 digitos originalmente). Nullable: una cuenta puede autenticarse solo por password.
    @Column
    @JsonIgnore
    private String pin;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(nullable = false)
    @Builder.Default
    private Boolean isEnabled = true;

    @Column(nullable = false)
    @Builder.Default
    private Integer failedLoginAttempts = 0;

    @Column
    private Instant lockedUntil;
}
