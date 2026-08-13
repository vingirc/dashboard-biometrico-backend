package com.biometria.telemetria_api.dto;

import com.biometria.telemetria_api.model.Role;

public record AuthResponse(String token, String username, Role role, long expiresInMs) {
}
