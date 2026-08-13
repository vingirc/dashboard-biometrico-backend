package com.biometria.telemetria_api.dto;

import com.biometria.telemetria_api.model.AuditEventType;

import java.time.Instant;
import java.util.UUID;

public record AuditLogResponse(UUID id, AuditEventType eventType, String actorUsername,
                               String targetUsername, String ipAddress, String detail, Instant createdAt) {
}
