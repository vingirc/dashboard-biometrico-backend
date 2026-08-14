package com.biometria.telemetria_api.controller;

import com.biometria.telemetria_api.config.SecurityConfig;
import com.biometria.telemetria_api.dto.TelemetryUserStatsResponse;
import com.biometria.telemetria_api.security.CsrfCookieFilter;
import com.biometria.telemetria_api.security.JwtAuthFilter;
import com.biometria.telemetria_api.security.JwtService;
import com.biometria.telemetria_api.service.TelemetryService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Igual que UserControllerTest: se importa el SecurityConfig real (y sus filtros) en vez de la
// seguridad por defecto del slice, porque lo que se comprueba aqui son *nuestras* reglas.
@WebMvcTest(TelemetryController.class)
@Import({SecurityConfig.class, JwtAuthFilter.class, CsrfCookieFilter.class, JwtService.class})
class TelemetryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TelemetryService telemetryService;

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminPuedeVerLasEstadisticasPorUsuario() throws Exception {
        when(telemetryService.getStatsByUser()).thenReturn(List.of(
                new TelemetryUserStatsResponse("ana", 4L, 105.25, 40, 200, 1L, 1L,
                        Instant.parse("2026-08-13T10:00:00Z"))));

        mockMvc.perform(get("/api/telemetry/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("ana"))
                .andExpect(jsonPath("$[0].totalReadings").value(4))
                .andExpect(jsonPath("$[0].avgHeartRate").value(105.25))
                .andExpect(jsonPath("$[0].criticalCount").value(1));
    }

    @Test
    @WithMockUser(roles = "USER")
    void usuarioSinRolAdminNoPuedeVerLasEstadisticas() throws Exception {
        mockMvc.perform(get("/api/telemetry/stats")).andExpect(status().isForbidden());

        verify(telemetryService, never()).getStatsByUser();
    }

    // 403 y no 401 por la misma razon documentada en UserControllerTest: sin formLogin ni httpBasic,
    // el punto de entrada por defecto de Spring Security es Http403ForbiddenEntryPoint.
    @Test
    void usuarioAnonimoNoPuedeVerLasEstadisticas() throws Exception {
        mockMvc.perform(get("/api/telemetry/stats")).andExpect(status().isForbidden());

        verify(telemetryService, never()).getStatsByUser();
    }

    // La regla de /stats es por ruta, sin verbo: ningun otro metodo se cuela sin ADMIN.
    @Test
    @WithMockUser(roles = "USER")
    void laRutaDeEstadisticasExigeAdminEnCualquierVerbo() throws Exception {
        mockMvc.perform(post("/api/telemetry/stats")).andExpect(status().isForbidden());

        verify(telemetryService, never()).getStatsByUser();
    }
}
