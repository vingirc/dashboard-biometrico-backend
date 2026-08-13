# Changelog

Todos los cambios relevantes de `telemetria-api` se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto se adhiere a [Versionado Semantico](https://semver.org/lang/es/).

## [1.0.0] - 2026-08-13

Primera version etiquetada. Consolida la plataforma de monitoreo biometrico y cierra los huecos
de operacion, documentacion y pruebas detectados en la auditoria de rubrica.

### Añadido

- **Actuator**: `spring-boot-starter-actuator` con `/actuator/health` y `/actuator/info` publicos
  (GET). Solo esos dos endpoints se exponen por HTTP y `health` va sin detalle. El goal `build-info`
  del plugin de Spring Boot hace que `/actuator/info` reporte version y fecha del build.
- **Swagger UI / OpenAPI**: `springdoc-openapi-starter-webmvc-ui` 3.1.0 (compilado contra Spring
  Boot 4.1.0). Documentacion navegable en `/swagger-ui.html` y esquema en `/v3/api-docs`.
- **Administracion completa de cuentas** (todo bajo `/api/users/**`, solo ADMIN):
  - `PATCH /api/users/{id}` — editar el username, con chequeo de unicidad que excluye la propia
    cuenta (409 si choca con otra).
  - `PATCH /api/users/{id}/role` — cambiar el rol.
  - `PATCH /api/users/{id}/pin` — reponer el PIN (mismo formato de 4-6 digitos que al crear) y
    levantar de paso el bloqueo por fuerza bruta pendiente.
- **Bitacora de auditoria**: entidad `AuditLog` + enum `AuditEventType`
  (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `USER_CREATED`, `USER_UPDATED`, `USER_ROLE_CHANGED`,
  `USER_PIN_RESET`, `USER_ENABLED`, `USER_DISABLED`). Registra quien hizo que sobre quien, con IP
  en los eventos de login; nunca guarda passwords, PINs, hashes ni tokens. Consultable en
  `GET /api/audit-logs` (ultimos 50, solo ADMIN).
- **Suite de tests (59)**: `AuthServiceTest` (incluye la comprobacion de que un usuario inexistente
  y una password incorrecta son indistinguibles), `UserServiceTest`, `UserControllerTest`
  (`@WebMvcTest` con las reglas reales de `SecurityConfig`: ADMIN/USER/anonimo y rechazo sin token
  CSRF), `PublicEndpointsTest` (lo que debe ser publico lo es, y el resto de actuator no) y
  `LoginRateLimiterTest`. Corren contra H2 en memoria, sin Docker ni PostgreSQL.
- **Integracion continua**: workflow `backend-ci.yml` (Java 21 + `./mvnw test`) en cada push y pull
  request que toque el backend.
- **Documentacion**: `README.md` del backend (stack, puesta en marcha, tests, endpoints, notas de
  seguridad) y `application-local.properties.example`, plantilla versionada de los secretos que una
  clonada nueva necesita definir.

### Modificado

- Version del proyecto de `0.0.1-SNAPSHOT` a `1.0.0`, y `<description>` del `pom.xml` rellenada.
- Los metodos de `UserService` que mutan estado ahora reciben el `Authentication` del que llama,
  para poder registrar el actor en la bitacora.
- Los endpoints de login registran cada intento sin cambiar lo que ve el cliente: el 401 generico
  anti-enumeracion se mantiene intacto.

### Notas

- `<url>` del `pom.xml` se dejo sin rellenar: el repositorio todavia no tiene remoto configurado.
- Un cliente anonimo recibe `403` (no `401`) en los endpoints protegidos. Es la conducta que ya
  tenia el proyecto: al desactivar `formLogin` y `httpBasic`, Spring Security usa
  `Http403ForbiddenEntryPoint` por defecto. El acceso queda denegado igual; queda anotado por si se
  quiere distinguir "no has iniciado sesion" de "no te alcanza el rol".
