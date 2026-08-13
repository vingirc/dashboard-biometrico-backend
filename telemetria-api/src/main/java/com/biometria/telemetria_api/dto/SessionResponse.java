package com.biometria.telemetria_api.dto;

import com.biometria.telemetria_api.model.Role;

// Lo unico que el cliente necesita saber tras autenticarse. El JWT en si nunca viaja en el body:
// vive solo en la cookie httpOnly, inaccesible para JavaScript (mitigacion contra robo via XSS).
public record SessionResponse(String username, Role role) {
}
