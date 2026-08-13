package com.biometria.telemetria_api.controller;

import com.biometria.telemetria_api.dto.TelemetryIngestRequest;
import com.biometria.telemetria_api.dto.TelemetryResponse;
import com.biometria.telemetria_api.service.TelemetryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/telemetry")
@RequiredArgsConstructor
public class TelemetryController {

    private final TelemetryService telemetryService;

    @GetMapping("/recent")
    public List<TelemetryResponse> recent(Authentication authentication) {
        return telemetryService.getRecent(authentication);
    }

    @PostMapping("/ingest")
    public ResponseEntity<TelemetryResponse> ingest(@RequestBody TelemetryIngestRequest request,
                                                      Authentication authentication) {
        TelemetryResponse saved = telemetryService.ingest(request, authentication);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }
}
