package com.biometria.telemetria_api.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LoginRateLimiterTest {

    private static final String IP = "203.0.113.10";

    @Test
    void permiteHastaElMaximoDeIntentosDentroDeLaVentana() {
        LoginRateLimiter limiter = new LoginRateLimiter(3, 60);

        assertThat(limiter.tryConsume(IP)).isTrue();
        assertThat(limiter.tryConsume(IP)).isTrue();
        assertThat(limiter.tryConsume(IP)).isTrue();
    }

    @Test
    void rechazaElIntentoSiguienteAlMaximo() {
        LoginRateLimiter limiter = new LoginRateLimiter(3, 60);
        limiter.tryConsume(IP);
        limiter.tryConsume(IP);
        limiter.tryConsume(IP);

        assertThat(limiter.tryConsume(IP)).isFalse();
    }

    @Test
    void contabilizaCadaIpPorSeparado() {
        LoginRateLimiter limiter = new LoginRateLimiter(1, 60);
        limiter.tryConsume(IP);

        assertThat(limiter.tryConsume(IP)).isFalse();
        assertThat(limiter.tryConsume("198.51.100.7")).isTrue();
    }

    @Test
    void vuelveAPermitirCuandoLaVentanaExpira() throws InterruptedException {
        LoginRateLimiter limiter = new LoginRateLimiter(1, 1);
        assertThat(limiter.tryConsume(IP)).isTrue();
        assertThat(limiter.tryConsume(IP)).isFalse();

        // La ventana deslizante se mide contra Instant.now() dentro del limitador, asi que la unica
        // forma de comprobar la expiracion es dejar pasar el tiempo real.
        Thread.sleep(1_100);

        assertThat(limiter.tryConsume(IP)).isTrue();
    }
}
