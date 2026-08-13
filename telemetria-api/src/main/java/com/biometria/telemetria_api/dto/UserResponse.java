package com.biometria.telemetria_api.dto;

import com.biometria.telemetria_api.model.Role;

import java.util.UUID;

public record UserResponse(UUID id, String username, Role role, boolean isEnabled) {
}
