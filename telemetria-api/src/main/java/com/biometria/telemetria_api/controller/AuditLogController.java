package com.biometria.telemetria_api.controller;

import com.biometria.telemetria_api.dto.AuditLogResponse;
import com.biometria.telemetria_api.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit-logs")
@RequiredArgsConstructor
public class AuditLogController {

    private final AuditLogService auditLogService;

    @GetMapping
    public List<AuditLogResponse> recent() {
        return auditLogService.recentLogs();
    }
}
