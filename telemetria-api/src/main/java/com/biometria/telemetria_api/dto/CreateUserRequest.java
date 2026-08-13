package com.biometria.telemetria_api.dto;

import com.biometria.telemetria_api.model.Role;

public record CreateUserRequest(String username, String password, String pin, Role role) {
}
