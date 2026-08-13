package com.biometria.telemetria_api.dto;

import java.util.List;

public record TelemetryIngestRequest(String userId, Integer heartRate, List<Double> accelerometer) {
}
