package com.biometria.telemetria_api.repository;

import com.biometria.telemetria_api.dto.TelemetryUserStatsResponse;
import com.biometria.telemetria_api.model.Role;
import com.biometria.telemetria_api.model.TelemetryRecord;
import com.biometria.telemetria_api.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

// La agregacion la hace la base, no Java: este slice la ejecuta de verdad (H2) en vez de confiar
// en que el JPQL "se ve bien". Cubre los tres casos que un GROUP BY mal escrito rompe en silencio:
// isLow nulo en filas viejas, lecturas anonimas sin usuario, y el promedio con division entera.
@DataJpaTest
class TelemetryRepositoryStatsTest {

    private static final Instant T0 = Instant.parse("2026-08-13T10:00:00Z");

    @Autowired
    private TelemetryRepository telemetryRepository;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void seed() {
        User ana = userRepository.save(User.builder().username("ana").role(Role.USER).build());
        User beto = userRepository.save(User.builder().username("beto").role(Role.USER).build());

        telemetryRepository.saveAll(List.of(
                record(ana, 80, T0.minusSeconds(40), false, false),
                record(ana, 200, T0.minusSeconds(30), true, false),
                record(ana, 40, T0.minusSeconds(10), false, true),
                // Fila "vieja": isLow nunca se calculo para ella.
                record(ana, 101, T0.minusSeconds(20), false, null),
                record(beto, 60, T0.minusSeconds(5), false, false),
                // Dispositivo anonimo: no debe aparecer en ningun grupo ni inflar los contadores.
                record(null, 250, T0.minusSeconds(1), true, false)));
        telemetryRepository.flush();
    }

    @Test
    void agregaUnaFilaPorUsuarioYExcluyeLasLecturasAnonimas() {
        List<TelemetryUserStatsResponse> stats = telemetryRepository.findStatsByUser();

        // Solo ana y beto: la lectura sin usuario queda fuera (y con ella su isCritical=true).
        assertThat(stats).extracting(TelemetryUserStatsResponse::username)
                .containsExactly("beto", "ana");
        assertThat(stats).extracting(TelemetryUserStatsResponse::criticalCount)
                .containsExactly(0L, 1L);
    }

    @Test
    void ordenaPorLaLecturaMasRecientePrimero() {
        List<TelemetryUserStatsResponse> stats = telemetryRepository.findStatsByUser();

        assertThat(stats.get(0).lastReadingAt()).isEqualTo(T0.minusSeconds(5));
        assertThat(stats.get(1).lastReadingAt()).isEqualTo(T0.minusSeconds(10));
    }

    @Test
    void calculaConteosYExtremosPorUsuario() {
        TelemetryUserStatsResponse ana = statsOf("ana");

        assertThat(ana.totalReadings()).isEqualTo(4L);
        assertThat(ana.minHeartRate()).isEqualTo(40);
        assertThat(ana.maxHeartRate()).isEqualTo(200);
        assertThat(ana.criticalCount()).isEqualTo(1L);
        // Una sola lectura baja: la fila con isLow=null no suma (NULL = true no es cierto en SQL).
        assertThat(ana.lowCount()).isEqualTo(1L);
    }

    // 421/4 = 105.25: si el promedio se calculara con division entera daria 105.
    @Test
    void elPromedioNoPierdeLosDecimales() {
        assertThat(statsOf("ana").avgHeartRate()).isEqualTo(105.25);
    }

    private TelemetryUserStatsResponse statsOf(String username) {
        return telemetryRepository.findStatsByUser().stream()
                .filter(s -> s.username().equals(username))
                .findFirst()
                .orElseThrow();
    }

    private static TelemetryRecord record(User user, int heartRate, Instant timestamp,
                                          boolean isCritical, Boolean isLow) {
        return TelemetryRecord.builder()
                .user(user)
                .heartRate(heartRate)
                .timestamp(timestamp)
                .isCritical(isCritical)
                .isLow(isLow)
                .build();
    }
}
