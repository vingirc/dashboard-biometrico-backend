package com.biometria.telemetria_api.security;

import com.biometria.telemetria_api.controller.AuthController;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

// Se ejecuta durante el handshake HTTP de SockJS/WebSocket (antes de que exista una sesion STOMP).
// El navegador manda la cookie httpOnly automaticamente en ese handshake (misma "site" que el backend,
// asi que SameSite=Lax no la bloquea). Si la cookie es valida, deja el Authentication en los atributos
// del handshake para que UserHandshakeHandler lo promueva a Principal de la sesion WebSocket.
//
// No rechaza el handshake solo por no traer cookie (permite que otros clientes, ej. un futuro wearable
// sin cookies, se autentiquen mas adelante via el header Authorization del frame CONNECT de STOMP,
// verificado por StompAuthChannelInterceptor). Solo rechaza si la cookie EXISTE pero es invalida/expirada.
@Component
@RequiredArgsConstructor
public class JwtHandshakeInterceptor implements HandshakeInterceptor {

    public static final String ATTR_PRINCIPAL = "principal";

    private final JwtService jwtService;

    @Override
    public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                    WebSocketHandler wsHandler, Map<String, Object> attributes) {
        if (!(request instanceof ServletServerHttpRequest servletRequest)) {
            return true;
        }

        Cookie[] cookies = servletRequest.getServletRequest().getCookies();
        String token = cookies == null ? null : Arrays.stream(cookies)
                .filter(cookie -> AuthController.COOKIE_NAME.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (token == null) {
            return true;
        }

        try {
            Claims claims = jwtService.parseClaims(token);
            String role = claims.get("role", String.class);
            List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
            attributes.put(ATTR_PRINCIPAL, new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities));
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        }
    }

    @Override
    public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response,
                                WebSocketHandler wsHandler, Exception exception) {
        // no-op
    }
}
