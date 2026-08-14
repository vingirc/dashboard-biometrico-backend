package com.biometria.telemetria_api.dto;

import java.time.Instant;

public record TelemetryUserStatsResponse(String username, long totalReadings, Double avgHeartRate,
                                         Integer minHeartRate, Integer maxHeartRate, long criticalCount,
                                         long lowCount, Instant lastReadingAt) {
}
