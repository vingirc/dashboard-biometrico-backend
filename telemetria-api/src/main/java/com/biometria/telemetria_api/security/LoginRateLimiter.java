package com.biometria.telemetria_api.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

// Limitador simple en memoria, por IP, con ventana deslizante. Complementa (no reemplaza) el bloqueo
// por cuenta de AuthService: este cubre el caso de alguien probando muchos usernames distintos desde
// la misma IP, donde el bloqueo por cuenta nunca se dispara para ninguna cuenta individual.
// Nota: usa request.getRemoteAddr(), que detras de un proxy/load balancer reportaria la IP del proxy,
// no la del cliente real -- suficiente para este proyecto, pero a tener en cuenta si se despliega detras de uno.
@Component
public class LoginRateLimiter {

    private final int maxAttempts;
    private final long windowSeconds;
    private final Map<String, Deque<Instant>> attemptsByIp = new ConcurrentHashMap<>();

    public LoginRateLimiter(
            @Value("${app.security.rate-limit.max-attempts}") int maxAttempts,
            @Value("${app.security.rate-limit.window-seconds}") long windowSeconds) {
        this.maxAttempts = maxAttempts;
        this.windowSeconds = windowSeconds;
    }

    public boolean tryConsume(String ip) {
        Deque<Instant> attempts = attemptsByIp.computeIfAbsent(ip, key -> new ConcurrentLinkedDeque<>());
        Instant cutoff = Instant.now().minusSeconds(windowSeconds);

        synchronized (attempts) {
            while (!attempts.isEmpty() && attempts.peekFirst().isBefore(cutoff)) {
                attempts.pollFirst();
            }
            if (attempts.size() >= maxAttempts) {
                return false;
            }
            attempts.addLast(Instant.now());
            return true;
        }
    }
}
