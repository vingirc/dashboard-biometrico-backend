package com.biometria.telemetria_api.config;

import com.biometria.telemetria_api.security.JwtHandshakeInterceptor;
import com.biometria.telemetria_api.security.PrincipalHandshakeHandler;
import com.biometria.telemetria_api.security.StompAuthChannelInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketTransportRegistration;

@Configuration
@EnableWebSocketMessageBroker
@RequiredArgsConstructor
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final StompAuthChannelInterceptor stompAuthChannelInterceptor;
    private final JwtHandshakeInterceptor jwtHandshakeInterceptor;

    @Value("${app.cors.allowed-origin}")
    private String allowedOrigin;

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic");
        registry.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // setAllowedOrigins valida el header Origin en el handshake (mitigacion OWASP contra
        // Cross-Site WebSocket Hijacking). No sustituye la autenticacion, pero reduce la superficie
        // a clientes que se presentan como el propio frontend.
        registry.addEndpoint("/ws")
                .setAllowedOrigins(allowedOrigin)
                .addInterceptors(jwtHandshakeInterceptor)
                .setHandshakeHandler(new PrincipalHandshakeHandler())
                .withSockJS();
    }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        // Orden importa: 1) stompAuthChannelInterceptor puebla accessor.getUser() a partir de la cookie
        // (handshake) o el header Authorization del CONNECT; 2) SecurityContextChannelInterceptor copia
        // ese Principal al SecurityContext del hilo que procesa el mensaje (el hilo de mensajeria STOMP
        // no hereda el SecurityContext del hilo HTTP original); 3) AuthorizationChannelInterceptor recien
        // ahi puede leerlo para autorizar por destino -- sin el paso 2, siempre ve SecurityContext vacio.
        registration.interceptors(
                stompAuthChannelInterceptor,
                new SecurityContextChannelInterceptor(),
                new AuthorizationChannelInterceptor(messageAuthorizationManager()));
    }

    @Override
    public void configureWebSocketTransport(WebSocketTransportRegistration registry) {
        // Limites defensivos contra DoS (frames enormes o clientes lentos que agotan buffers en el servidor).
        registry.setMessageSizeLimit(8 * 1024);
        registry.setSendTimeLimit(10 * 1000);
        registry.setSendBufferSizeLimit(512 * 1024);
    }

    // Autorizacion a nivel de destino STOMP: sin esto, cualquier cliente autenticado (aunque sea con
    // rol USER) podria suscribirse manualmente al topic de otra cuenta o al de ADMIN con un cliente
    // STOMP crudo, sin pasar por la UI del frontend.
    @Bean
    public AuthorizationManager<Message<?>> messageAuthorizationManager() {
        return MessageMatcherDelegatingAuthorizationManager.builder()
                .simpSubscribeDestMatchers("/topic/telemetry-admin").hasRole("ADMIN")
                .simpSubscribeDestMatchers("/topic/telemetry/{username}")
                        .access((authentication, context) -> {
                            String username = context.getVariables().get("username");
                            boolean granted = authentication.get() != null
                                    && authentication.get().getName().equals(username);
                            return new AuthorizationDecision(granted);
                        })
                .simpDestMatchers("/app/**").authenticated()
                .anyMessage().authenticated()
                .build();
    }
}
