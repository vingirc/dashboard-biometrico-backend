package com.biometria.telemetria_api.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Arranca el contexto completo para comprobar que las rutas que deben ser publicas realmente lo son
// y que abrirlas no dejo colandose nada mas. Sin sesion en ninguna peticion.
@SpringBootTest
@AutoConfigureMockMvc
class PublicEndpointsTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void healthRespondeSinAutenticacion() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                // show-details=never: el detalle (base de datos, pool) no debe llegar a un anonimo.
                .andExpect(jsonPath("$.components").doesNotExist());
    }

    @Test
    void infoRespondeSinAutenticacion() throws Exception {
        mockMvc.perform(get("/actuator/info")).andExpect(status().isOk());
    }

    @Test
    void elEsquemaOpenApiEsPublico() throws Exception {
        mockMvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
    }

    // El resto de actuator queda fuera por partida doble: no esta en la lista blanca de exposicion
    // (no se mapea como ruta) y tampoco esta en el permitAll, asi que cae en el deny por defecto.
    @Test
    void losDemasEndpointsDeActuatorNoSonAccesibles() throws Exception {
        mockMvc.perform(get("/actuator/env")).andExpect(status().isForbidden());
        mockMvc.perform(get("/actuator/beans")).andExpect(status().isForbidden());
        mockMvc.perform(get("/actuator/heapdump")).andExpect(status().isForbidden());
    }

    @Test
    void losEndpointsDeNegocioSiguenProtegidos() throws Exception {
        mockMvc.perform(get("/api/users")).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/audit-logs")).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/telemetry/recent")).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/telemetry/stats")).andExpect(status().isForbidden());
    }
}
