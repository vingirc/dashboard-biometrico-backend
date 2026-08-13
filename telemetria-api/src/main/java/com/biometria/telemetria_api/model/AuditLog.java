package com.biometria.telemetria_api.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

// Bitacora de eventos de seguridad. Guarda solo *quien* hizo *que* sobre *quien*: nunca passwords,
// PINs, hashes ni tokens, para que el propio log no se convierta en material sensible.
@Entity
@Table(name = "audit_logs")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditEventType eventType;

    // Nullable: en un login fallido todavia no hay actor autenticado, y el username tecleado
    // puede no corresponder a ninguna cuenta real.
    @Column
    private String actorUsername;

    @Column
    private String targetUsername;

    @Column
    private String ipAddress;

    @Column
    private String detail;

    @Column(nullable = false)
    private Instant createdAt;
}
