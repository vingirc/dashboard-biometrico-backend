package com.biometria.telemetria_api.service;

import com.biometria.telemetria_api.dto.TelemetryIngestRequest;
import com.biometria.telemetria_api.dto.TelemetryResponse;
import com.biometria.telemetria_api.dto.TelemetryUserStatsResponse;
import com.biometria.telemetria_api.model.TelemetryRecord;
import com.biometria.telemetria_api.model.User;
import com.biometria.telemetria_api.repository.TelemetryRepository;
import com.biometria.telemetria_api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TelemetryService {

    private static final int CRITICAL_THRESHOLD_BPM = 160;
    private static final int LOW_THRESHOLD_BPM = 50;
    private static final String ADMIN_TOPIC = "/topic/telemetry-admin";
    private static final String USER_TOPIC_PREFIX = "/topic/telemetry/";

    private final TelemetryRepository telemetryRepository;
    private final UserRepository userRepository;
    private final SimpMessagingTemplate messagingTemplate;

    // ADMIN ve todo el historial; USER solo las lecturas vinculadas a su propia cuenta
    // (las anonimas, con user=null, nunca matchean ningun username y quedan fuera para ellos).
    public List<TelemetryResponse> getRecent(Authentication authentication) {
        List<TelemetryRecord> records = isAdmin(authentication)
                ? telemetryRepository.findTop50ByOrderByTimestampDesc()
                : telemetryRepository.findTop50ByUserUsernameOrderByTimestampDesc(authentication.getName());

        return records.stream().map(this::toResponse).toList();
    }

    // Estadisticas agregadas de TODOS los usuarios: solo para ADMIN. No recibe Authentication ni
    // filtra por llamante a proposito -- el control de acceso vive en SecurityConfig
    // (/api/telemetry/stats -> hasRole("ADMIN")), no duplicado aqui.
    public List<TelemetryUserStatsResponse> getStatsByUser() {
        return telemetryRepository.findStatsByUser();
    }

    public TelemetryResponse ingest(TelemetryIngestRequest request, Authentication authentication) {
        if (request.userId() == null || request.userId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "userId es requerido");
        }
        if (request.heartRate() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "heartRate es requerido");
        }
        if (request.accelerometer() != null && request.accelerometer().size() != 3) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El vector del acelerometro debe tener 3 componentes (x, y, z)");
        }

        // Si el userId corresponde a una cuenta registrada, quien manda la request debe SER esa cuenta
        // (autenticada) y esa cuenta debe estar habilitada -- si no, se rechaza con un mensaje generico
        // que no distingue "no sos vos" de "cuenta deshabilitada" (evita filtrar el estado de la cuenta
        // a quien no demostro ser su dueño). Si el userId no corresponde a ninguna cuenta conocida, se
        // permite sin autenticacion (dispositivo anonimo/no registrado, comportamiento sin cambios).
        Optional<User> maybeUser = userRepository.findByUsername(request.userId());
        if (maybeUser.isPresent()) {
            User user = maybeUser.get();
            boolean isOwner = authentication != null && authentication.getName().equals(user.getUsername());
            boolean usable = isOwner && Boolean.TRUE.equals(user.getIsEnabled());
            if (!usable) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "No autorizado para enviar telemetria en nombre de esta cuenta");
            }
        }

        List<Double> accel = request.accelerometer();
        TelemetryRecord record = TelemetryRecord.builder()
                .user(maybeUser.orElse(null))
                .heartRate(request.heartRate())
                .timestamp(Instant.now())
                .isCritical(request.heartRate() > CRITICAL_THRESHOLD_BPM)
                // heartRate > 0 a proposito: un 0 es una lectura invalida/sin señal (ver TelemetryService
                // en el cliente Wear OS, que nunca deberia mandar uno), no es lo mismo que "pulso bajo".
                .isLow(request.heartRate() > 0 && request.heartRate() < LOW_THRESHOLD_BPM)
                .accelX(accel != null ? accel.get(0) : null)
                .accelY(accel != null ? accel.get(1) : null)
                .accelZ(accel != null ? accel.get(2) : null)
                .build();

        TelemetryResponse response = toResponse(telemetryRepository.save(record));

        // Practicas 9/10: cada ingesta se empuja de inmediato por WebSocket. ADMIN recibe todo por su
        // topic dedicado; si la lectura quedo vinculada a un usuario, tambien se manda a su topic personal
        // (nadie mas puede suscribirse a ese topic -- ver la autorizacion por destino en WebSocketConfig).
        messagingTemplate.convertAndSend(ADMIN_TOPIC, response);
        maybeUser.ifPresent(user -> messagingTemplate.convertAndSend(USER_TOPIC_PREFIX + user.getUsername(), response));

        return response;
    }

    private boolean isAdmin(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_ADMIN"::equals);
    }

    private TelemetryResponse toResponse(TelemetryRecord record) {
        String username = record.getUser() != null ? record.getUser().getUsername() : null;
        List<Double> accelerometer = record.getAccelX() != null
                ? List.of(record.getAccelX(), record.getAccelY(), record.getAccelZ())
                : null;
        return new TelemetryResponse(record.getId(), username, record.getHeartRate(), record.getTimestamp(),
                record.getIsCritical(), record.getIsLow(), accelerometer);
    }
}
