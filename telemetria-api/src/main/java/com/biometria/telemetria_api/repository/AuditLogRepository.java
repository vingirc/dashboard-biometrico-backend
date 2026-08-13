package com.biometria.telemetria_api.repository;

import com.biometria.telemetria_api.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    List<AuditLog> findTop50ByOrderByCreatedAtDesc();
}
