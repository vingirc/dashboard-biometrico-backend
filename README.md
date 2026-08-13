# Backend — telemetria-api

API REST + WebSocket de la plataforma de monitoreo biometrico. Recibe telemetria de wearables,
la difunde en tiempo real al dashboard y administra las cuentas de usuario.

> **El proyecto Maven esta anidado en `telemetria-api/`, no en esta carpeta.**
> Todos los comandos (`./mvnw ...`) se ejecutan desde `backend-springboot/telemetria-api/`.
> Esta carpeta solo agrupa la documentacion del backend.

## Stack

| Pieza | Version |
|---|---|
| Java | 21 |
| Spring Boot | 4.1.0 (Web MVC, Security, Data JPA, WebSocket, Actuator) |
| PostgreSQL | 15 (via Docker) |
| JWT | jjwt 0.12.6 |
| OpenAPI | springdoc-openapi 3.1.0 |
| Tests | JUnit 5, Mockito, spring-security-test, H2 en memoria |

## Requisitos

- JDK 21 (`java -version` debe reportar 21; el wrapper `./mvnw` se encarga de Maven)
- Docker y Docker Compose (para PostgreSQL)

## Puesta en marcha local

```bash
cd telemetria-api

# 1. Levantar PostgreSQL (expone el 5432 del contenedor en el 5434 del host)
docker compose up -d

# 2. Crear el archivo de secretos locales a partir de la plantilla versionada
cp src/main/resources/application-local.properties.example \
   src/main/resources/application-local.properties
#    ...y rellenar DB_PASSWORD, JWT_SECRET y ADMIN_PASSWORD.
#    DB_PASSWORD debe coincidir con POSTGRES_PASSWORD del docker-compose.yaml.
#    JWT_SECRET necesita 32 caracteres o mas (HMAC-SHA256).

# 3. Arrancar la API en http://localhost:8080
./mvnw spring-boot:run
```

En el primer arranque, si no existe ningun usuario con rol `ADMIN`, `AdminSeeder` crea uno con el
username `ADMIN_USERNAME` (por defecto `admin`) y el password `ADMIN_PASSWORD`. Cambialo despues
del primer login.

`application-local.properties` esta en `.gitignore`: los secretos nunca se versionan. En CI o en un
despliegue real no hace falta el archivo, basta con definir las variables de entorno `DB_PASSWORD`,
`JWT_SECRET` y `ADMIN_PASSWORD`.

## Tests

```bash
cd telemetria-api
./mvnw test
```

No requieren Docker ni PostgreSQL: `src/test/resources/application.properties` apunta los tests a
una base H2 en memoria y define secretos de prueba. Es lo mismo que corre el workflow
`.github/workflows/backend-ci.yml` en cada push y pull request.

## Enlaces utiles (con la app corriendo)

| Recurso | URL |
|---|---|
| Health check | http://localhost:8080/actuator/health |
| Info del build | http://localhost:8080/actuator/info |
| Swagger UI | http://localhost:8080/swagger-ui.html |
| OpenAPI JSON | http://localhost:8080/v3/api-docs |

Solo `health` e `info` estan expuestos por HTTP (lista blanca en `application.properties`), y
`health` no muestra detalle, asi que no filtra la configuracion interna.

## Endpoints

| Metodo | Ruta | Acceso |
|---|---|---|
| POST | `/api/auth/login` | publico |
| POST | `/api/auth/login-pin` | publico |
| GET | `/api/auth/me` | autenticado |
| POST | `/api/auth/logout` | publico |
| POST | `/api/telemetry/ingest` | publico (dispositivos) |
| GET | `/api/telemetry/recent` | autenticado |
| GET | `/api/users` | ADMIN |
| POST | `/api/users` | ADMIN |
| PATCH | `/api/users/{id}` | ADMIN (editar username) |
| PATCH | `/api/users/{id}/role` | ADMIN |
| PATCH | `/api/users/{id}/pin` | ADMIN (reponer PIN) |
| PATCH | `/api/users/{id}/disable` | ADMIN |
| PATCH | `/api/users/{id}/enable` | ADMIN |
| GET | `/api/audit-logs` | ADMIN |

WebSocket STOMP en `/ws`: el broker publica en `/topic/telemetry` (ADMIN, todo el trafico) y en
`/topic/telemetry/{username}` (cada usuario, solo lo suyo).

## Notas de seguridad

- **Autenticacion**: JWT. El dashboard web lo recibe en una cookie `httpOnly` (no accesible desde
  JavaScript); los clientes nativos usan el header `Authorization: Bearer`.
- **CSRF**: patron doble-submit cookie para el flujo de navegador. Las peticiones que llevan header
  `Authorization` quedan exentas, porque un sitio atacante no puede forjar ese header.
- **Fuerza bruta**: bloqueo por cuenta tras N intentos fallidos (`app.security.lockout.*`) y rate
  limiting por IP en los endpoints de login (`app.security.rate-limit.*`).
- **Anti-enumeracion**: usuario inexistente, cuenta deshabilitada, cuenta bloqueada y credencial
  incorrecta responden todos el mismo 401 generico.
- **Bitacora**: logins (exitosos y fallidos) y cambios sobre cuentas quedan en `audit_logs`,
  consultables por un ADMIN en `/api/audit-logs`.
