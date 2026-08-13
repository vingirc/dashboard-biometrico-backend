package com.biometria.telemetria_api.config;

import com.biometria.telemetria_api.security.CsrfCookieFilter;
import com.biometria.telemetria_api.security.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final CsrfCookieFilter csrfCookieFilter;

    @Value("${app.cors.allowed-origin}")
    private String allowedOrigin;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // Doble-submit cookie: Spring pone un token XSRF-TOKEN legible por JS (no httpOnly);
                // el cliente debe reenviarlo en el header X-XSRF-TOKEN en cada request que muta estado.
                // Un sitio atacante no puede leer esa cookie (same-origin policy) ni forjar el header,
                // asi que no puede completar el "doble submit" aunque el navegador mande la cookie de auth sola.
                // Necesario ahora que el JWT vive en una cookie (se envia automaticamente, a diferencia
                // del header Authorization de antes, que un sitio externo nunca podia forjar).
                .csrf(csrf -> {
                    CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
                    // Desactiva el wrapper de carga diferida (proteccion BREACH pensada para vistas
                    // server-side): sin esto, la cookie XSRF-TOKEN nunca se emite en una SPA pura.
                    requestHandler.setCsrfRequestAttributeName(null);
                    csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                            .csrfTokenRequestHandler(requestHandler)
                            .ignoringRequestMatchers("/api/auth/login", "/api/auth/login-pin", "/api/telemetry/**")
                            // Clientes nativos (Wear OS, etc.) autentican con el header Authorization: Bearer,
                            // nunca con la cookie -- son inmunes a CSRF por construccion, ya que un sitio
                            // atacante no puede forzar al navegador de la victima a adjuntar un header
                            // Authorization arbitrario en una request cross-site. El doble-submit cookie
                            // solo protege al flujo basado en cookie (frontend web); exigirlo tambien a estos
                            // clientes los bloquearia siempre (nunca tienen la cookie XSRF-TOKEN que leer).
                            .ignoringRequestMatchers(request -> request.getHeader("Authorization") != null);
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/api/auth/login-pin", "/api/auth/logout").permitAll()
                        // El ingest sigue publico (dispositivos anonimos); la autorizacion fina
                        // (¿sos vos esa cuenta?) se resuelve dentro de TelemetryService, no aqui.
                        .requestMatchers(HttpMethod.POST, "/api/telemetry/ingest").permitAll()
                        // La lectura ya no es publica: se filtra por usuario autenticado (ADMIN ve todo).
                        .requestMatchers(HttpMethod.GET, "/api/telemetry/recent").authenticated()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/ws/**").permitAll()
                        // Sondas de monitoreo: solo health e info (lista blanca en application.properties),
                        // y sin detalle (show-details=never), asi que no filtran configuracion interna.
                        // Sin este permitAll caerian en anyRequest().authenticated() y responderian 401.
                        .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/info").permitAll()
                        // Documentacion de la API. Publica a proposito para poder revisarla desde el navegador
                        // sin sesion; describe la forma de los endpoints, nunca datos ni credenciales.
                        .requestMatchers(HttpMethod.GET, "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/api/users/**").hasRole("ADMIN")
                        // Con /** (igual que /api/users/**) cualquier subruta que se agregue despues
                        // nace exigiendo ADMIN, en vez de caer en el authenticated() generico.
                        .requestMatchers("/api/audit-logs/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(csrfCookieFilter, CsrfFilter.class);

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(allowedOrigin));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        // Solo los headers que el frontend realmente envia (evita el comodin "*", menos superficie de ataque).
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-XSRF-TOKEN"));
        // Necesario para que el navegador mande/reciba la cookie httpOnly de auth en requests cross-origin
        // (frontend :4200, backend :8080). Combinado con un origen explicito (nunca "*"), como exige CORS.
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }
}
