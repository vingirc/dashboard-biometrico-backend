package com.biometria.telemetria_api.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "telemetry_records")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TelemetryRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Nullable: permite telemetria de dispositivos anonimos/no registrados, y preserva las filas
    // de prueba existentes (sin usuario asociado) al introducir esta relacion.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false)
    private Integer heartRate;

    @Column(nullable = false)
    private Instant timestamp;

    @Column(nullable = false)
    private Boolean isCritical;

    // Nullable a proposito (a diferencia de isCritical, que ya existia desde que la tabla estaba
    // vacia): ddl-auto=update no puede agregar una columna NOT NULL a una tabla con filas
    // existentes sin un DEFAULT. Las filas viejas quedan con isLow=NULL, lo cual es correcto --
    // nunca se calculo ese dato para ellas.
    private Boolean isLow;

    // Vector del acelerometro (x, y, z). Nullable: no todos los dispositivos lo mandan.
    @Column(name = "accel_x")
    private Double accelX;

    @Column(name = "accel_y")
    private Double accelY;

    @Column(name = "accel_z")
    private Double accelZ;
}
