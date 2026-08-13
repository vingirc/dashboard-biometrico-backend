package com.biometria.telemetria_api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Spring Security 6 carga el CsrfToken de forma diferida (proteccion BREACH) -- normalmente solo se
// resuelve si algo (ej. una vista server-side) toca el atributo de request "_csrf". En una SPA pura eso
// nunca pasa, asi que la cookie XSRF-TOKEN jamas se emitia. Este filtro fuerza esa resolucion en cada
// request para que la cookie siempre este disponible y el patron doble-submit funcione.
// Patron oficial documentado por Spring Security para SPA + cookie CSRF.
@Component
public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            csrfToken.getToken();
        }
        filterChain.doFilter(request, response);
    }
}
