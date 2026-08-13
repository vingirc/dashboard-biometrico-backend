package com.biometria.telemetria_api.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

// DTO de salida para telemetria: nunca se serializa la entidad User completa (evita filtrar password/pin hasheados).
public record TelemetryResponse(UUID id, String username, Integer heartRate, Instant timestamp, Boolean isCritical,
                                 Boolean isLow, List<Double> accelerometer) {
}
