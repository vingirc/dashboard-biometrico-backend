package com.biometria.telemetria_api.security;

import org.springframework.http.server.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;

import java.security.Principal;
import java.util.Map;

// Promueve el Authentication que JwtHandshakeInterceptor dejo en los atributos del handshake (si la
// cookie era valida) a Principal de la sesion WebSocket -- asi accessor.getUser() ya viene poblado
// cuando llega el frame CONNECT de STOMP, sin depender de headers que el navegador no puede enviar
// en un WebSocket nativo.
public class PrincipalHandshakeHandler extends DefaultHandshakeHandler {

    @Override
    protected Principal determineUser(ServerHttpRequest request, WebSocketHandler wsHandler,
                                       Map<String, Object> attributes) {
        Object principal = attributes.get(JwtHandshakeInterceptor.ATTR_PRINCIPAL);
        return principal instanceof Authentication authentication ? authentication : null;
    }
}
