package com.biometria.telemetria_api.controller;

import com.biometria.telemetria_api.dto.ChangeRoleRequest;
import com.biometria.telemetria_api.dto.CreateUserRequest;
import com.biometria.telemetria_api.dto.ResetPinRequest;
import com.biometria.telemetria_api.dto.UpdateUserRequest;
import com.biometria.telemetria_api.dto.UserResponse;
import com.biometria.telemetria_api.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    public List<UserResponse> list() {
        return userService.listUsers();
    }

    @PostMapping
    public ResponseEntity<UserResponse> create(@RequestBody CreateUserRequest request, Authentication authentication) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(request, authentication));
    }

    @PatchMapping("/{id}")
    public UserResponse update(@PathVariable UUID id, @RequestBody UpdateUserRequest request,
                               Authentication authentication) {
        return userService.updateUser(id, request, authentication);
    }

    @PatchMapping("/{id}/role")
    public UserResponse changeRole(@PathVariable UUID id, @RequestBody ChangeRoleRequest request,
                                   Authentication authentication) {
        return userService.changeRole(id, request, authentication);
    }

    @PatchMapping("/{id}/pin")
    public UserResponse resetPin(@PathVariable UUID id, @RequestBody ResetPinRequest request,
                                 Authentication authentication) {
        return userService.resetPin(id, request, authentication);
    }

    @PatchMapping("/{id}/disable")
    public UserResponse disable(@PathVariable UUID id, Authentication authentication) {
        return userService.disableUser(id, authentication);
    }

    @PatchMapping("/{id}/enable")
    public UserResponse enable(@PathVariable UUID id, Authentication authentication) {
        return userService.enableUser(id, authentication);
    }
}
