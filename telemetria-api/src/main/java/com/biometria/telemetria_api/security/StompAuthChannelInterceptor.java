package com.biometria.telemetria_api.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

// Autentica el frame CONNECT de STOMP. El handshake HTTP de SockJS (/ws/info, /ws/websocket) se deja
// permitAll a proposito. Dos caminos posibles llegando aqui:
//  1) El navegador ya trae la cookie httpOnly -- JwtHandshakeInterceptor + PrincipalHandshakeHandler ya
//     poblaron accessor.getUser() durante el handshake, antes de que exista este frame CONNECT.
//  2) Un cliente sin cookies (ej. un futuro dispositivo) manda su propio header Authorization dentro
//     del frame CONNECT -- se valida aqui igual que antes.
// Si ninguno de los dos aplica, se rechaza la conexion STOMP.
@Component
@RequiredArgsConstructor
public class StompAuthChannelInterceptor implements ChannelInterceptor {

    private final JwtService jwtService;

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

        if (accessor != null && StompCommand.CONNECT.equals(accessor.getCommand())) {
            if (accessor.getUser() != null) {
                // Ya autenticado via cookie en el handshake.
                return message;
            }

            String header = accessor.getFirstNativeHeader("Authorization");
            if (header == null || !header.startsWith("Bearer ")) {
                throw new AccessDeniedException("Falta la cookie de sesion o el token JWT en el CONNECT de STOMP");
            }

            try {
                Claims claims = jwtService.parseClaims(header.substring(7));
                String role = claims.get("role", String.class);
                var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
                var authentication = new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
                accessor.setUser(authentication);
            } catch (JwtException | IllegalArgumentException ex) {
                throw new AccessDeniedException("Token JWT invalido o expirado");
            }
        }

        return message;
    }
}
