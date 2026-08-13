package com.biometria.telemetria_api.controller;

import com.biometria.telemetria_api.config.SecurityConfig;
import com.biometria.telemetria_api.dto.UserResponse;
import com.biometria.telemetria_api.model.Role;
import com.biometria.telemetria_api.security.CsrfCookieFilter;
import com.biometria.telemetria_api.security.JwtAuthFilter;
import com.biometria.telemetria_api.security.JwtService;
import com.biometria.telemetria_api.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Se importa el SecurityConfig real (y los filtros de los que depende) en vez de la seguridad por
// defecto del slice: lo que se quiere comprobar aqui son *nuestras* reglas de autorizacion.
@WebMvcTest(UserController.class)
@Import({SecurityConfig.class, JwtAuthFilter.class, CsrfCookieFilter.class, JwtService.class})
class UserControllerTest {

    private static final UUID USER_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserService userService;

    // ---------- control de acceso ----------

    @Test
    @WithMockUser(roles = "ADMIN")
    void adminPuedeListarUsuarios() throws Exception {
        when(userService.listUsers()).thenReturn(List.of(new UserResponse(USER_ID, "ana", Role.USER, true)));

        mockMvc.perform(get("/api/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("ana"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void usuarioSinRolAdminNoPuedeListarUsuarios() throws Exception {
        mockMvc.perform(get("/api/users")).andExpect(status().isForbidden());

        verify(userService, never()).listUsers();
    }

    // Un anonimo se rechaza con 403, no con 401: al desactivar formLogin y httpBasic, Spring Security
    // se queda con Http403ForbiddenEntryPoint como punto de entrada por defecto. El acceso queda
    // igualmente denegado (el servicio nunca se invoca); lo que cambia es el codigo que ve el cliente.
    // Este test fija esa conducta actual -- si algun dia se quiere 401 para distinguir "no has entrado"
    // de "no te alcanza el rol", hay que declarar un authenticationEntryPoint explicito.
    @Test
    void usuarioAnonimoNoPuedeListarUsuarios() throws Exception {
        mockMvc.perform(get("/api/users")).andExpect(status().isForbidden());

        verify(userService, never()).listUsers();
    }

    @Test
    @WithMockUser(roles = "USER")
    void usuarioSinRolAdminNoPuedeCambiarRoles() throws Exception {
        mockMvc.perform(patch("/api/users/{id}/role", USER_ID)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isForbidden());

        verify(userService, never()).changeRole(any(), any(), any());
    }

    // Escalada de privilegios por CSRF: sin token, una peticion que muta estado se rechaza aunque
    // la sesion del navegador sea de un ADMIN legitimo.
    @Test
    @WithMockUser(roles = "ADMIN")
    void unaPeticionQueMutaSinTokenCsrfSeRechaza() throws Exception {
        mockMvc.perform(patch("/api/users/{id}/role", USER_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isForbidden());

        verify(userService, never()).changeRole(any(), any(), any());
    }

    // ---------- create ----------

    @Test
    @WithMockUser(roles = "ADMIN")
    void crearUsuarioDevuelve201() throws Exception {
        when(userService.createUser(any(), any())).thenReturn(new UserResponse(USER_ID, "ana", Role.USER, true));

        mockMvc.perform(post("/api/users")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"ana\",\"password\":\"password-larga\",\"role\":\"USER\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("ana"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void crearUsuarioInvalidoPropagaEl400DelServicio() throws Exception {
        when(userService.createUser(any(), any()))
                .thenThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "username es requerido"));

        mockMvc.perform(post("/api/users")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    // ---------- update ----------

    @Test
    @WithMockUser(roles = "ADMIN")
    void editarUsernameDevuelve200() throws Exception {
        when(userService.updateUser(eq(USER_ID), any(), any()))
                .thenReturn(new UserResponse(USER_ID, "ana2", Role.USER, true));

        mockMvc.perform(patch("/api/users/{id}", USER_ID)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"ana2\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("ana2"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void editarUsernameDuplicadoPropagaEl409DelServicio() throws Exception {
        when(userService.updateUser(eq(USER_ID), any(), any()))
                .thenThrow(new ResponseStatusException(HttpStatus.CONFLICT, "El username ya existe"));

        mockMvc.perform(patch("/api/users/{id}", USER_ID)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"beto\"}"))
                .andExpect(status().isConflict());
    }

    // ---------- role ----------

    @Test
    @WithMockUser(roles = "ADMIN")
    void cambiarRolDevuelve200() throws Exception {
        when(userService.changeRole(eq(USER_ID), any(), any()))
                .thenReturn(new UserResponse(USER_ID, "ana", Role.ADMIN, true));

        mockMvc.perform(patch("/api/users/{id}/role", USER_ID)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void cambiarRolAUnValorInexistenteDevuelve400() throws Exception {
        mockMvc.perform(patch("/api/users/{id}/role", USER_ID)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"SUPERADMIN\"}"))
                .andExpect(status().isBadRequest());

        verify(userService, never()).changeRole(any(), any(), any());
    }

    // ---------- pin ----------

    @Test
    @WithMockUser(roles = "ADMIN")
    void reponerPinDevuelve200() throws Exception {
        when(userService.resetPin(eq(USER_ID), any(), any()))
                .thenReturn(new UserResponse(USER_ID, "ana", Role.USER, true));

        mockMvc.perform(patch("/api/users/{id}/pin", USER_ID)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"pin\":\"4321\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void reponerPinInvalidoPropagaEl400DelServicio() throws Exception {
        when(userService.resetPin(eq(USER_ID), any(), any()))
                .thenThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "El pin debe tener entre 4 y 6 digitos numericos"));

        mockMvc.perform(patch("/api/users/{id}/pin", USER_ID)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"pin\":\"12\"}"))
                .andExpect(status().isBadRequest());
    }

    // ---------- enable / disable ----------

    @Test
    @WithMockUser(roles = "ADMIN")
    void deshabilitarUsuarioDevuelve200() throws Exception {
        when(userService.disableUser(eq(USER_ID), any()))
                .thenReturn(new UserResponse(USER_ID, "ana", Role.USER, false));

        mockMvc.perform(patch("/api/users/{id}/disable", USER_ID).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isEnabled").value(false));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void deshabilitarUsuarioInexistentePropagaEl404DelServicio() throws Exception {
        when(userService.disableUser(eq(USER_ID), any()))
                .thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado"));

        mockMvc.perform(patch("/api/users/{id}/disable", USER_ID).with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void habilitarUsuarioDevuelve200() throws Exception {
        when(userService.enableUser(eq(USER_ID), any()))
                .thenReturn(new UserResponse(USER_ID, "ana", Role.USER, true));

        mockMvc.perform(patch("/api/users/{id}/enable", USER_ID).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isEnabled").value(true));
    }
}
