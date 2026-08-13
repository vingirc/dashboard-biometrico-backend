package com.biometria.telemetria_api.repository;

import com.biometria.telemetria_api.model.TelemetryRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface TelemetryRepository extends JpaRepository<TelemetryRecord, UUID> {

    List<TelemetryRecord> findTop50ByOrderByTimestampDesc();

    List<TelemetryRecord> findTop50ByUserUsernameOrderByTimestampDesc(String username);
}
