package com.biometria.telemetria_api.repository;

import com.biometria.telemetria_api.dto.TelemetryUserStatsResponse;
import com.biometria.telemetria_api.model.TelemetryRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface TelemetryRepository extends JpaRepository<TelemetryRecord, UUID> {

    List<TelemetryRecord> findTop50ByOrderByTimestampDesc();

    List<TelemetryRecord> findTop50ByUserUsernameOrderByTimestampDesc(String username);

    // Agrega en la base (no en memoria): una fila por usuario, sin traerse el historial completo.
    // Las lecturas anonimas (user = null) quedan fuera: no tienen username por el cual agrupar.
    // El CASE de isLow tolera los NULL de las filas viejas -- en SQL 'NULL = true' no es cierto,
    // asi que esas lecturas caen en el ELSE y suman 0, que es justo lo que se quiere (nunca se
    // calculo isLow para ellas, no es que se supiera que el pulso no era bajo).
    @Query("""
            SELECT new com.biometria.telemetria_api.dto.TelemetryUserStatsResponse(
                t.user.username,
                COUNT(t),
                AVG(t.heartRate),
                MIN(t.heartRate),
                MAX(t.heartRate),
                SUM(CASE WHEN t.isCritical = true THEN 1L ELSE 0L END),
                SUM(CASE WHEN t.isLow = true THEN 1L ELSE 0L END),
                MAX(t.timestamp))
            FROM TelemetryRecord t
            WHERE t.user IS NOT NULL
            GROUP BY t.user.username
            ORDER BY MAX(t.timestamp) DESC
            """)
    List<TelemetryUserStatsResponse> findStatsByUser();
}
