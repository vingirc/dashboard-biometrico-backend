package com.biometria.telemetria_api.service;

import com.biometria.telemetria_api.dto.AuditLogResponse;
import com.biometria.telemetria_api.model.AuditEventType;
import com.biometria.telemetria_api.model.AuditLog;
import com.biometria.telemetria_api.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    // Los eventos de login registran el username *tecleado*, que es entrada libre del cliente.
    // Se recorta para que nadie pueda inflar la tabla (ni la respuesta de /api/audit-logs)
    // mandando cadenas enormes al formulario de login.
    private static final int MAX_FIELD_LENGTH = 120;

    private final AuditLogRepository auditLogRepository;

    public void record(AuditEventType eventType, String actorUsername, String targetUsername,
                       String ipAddress, String detail) {
        auditLogRepository.save(AuditLog.builder()
                .eventType(eventType)
                .actorUsername(truncate(actorUsername))
                .targetUsername(truncate(targetUsername))
                .ipAddress(truncate(ipAddress))
                .detail(truncate(detail))
                .createdAt(Instant.now())
                .build());
    }

    public List<AuditLogResponse> recentLogs() {
        return auditLogRepository.findTop50ByOrderByCreatedAtDesc().stream()
                .map(log -> new AuditLogResponse(log.getId(), log.getEventType(), log.getActorUsername(),
                        log.getTargetUsername(), log.getIpAddress(), log.getDetail(), log.getCreatedAt()))
                .toList();
    }

    private String truncate(String value) {
        if (value == null || value.length() <= MAX_FIELD_LENGTH) {
            return value;
        }
        return value.substring(0, MAX_FIELD_LENGTH);
    }
}
