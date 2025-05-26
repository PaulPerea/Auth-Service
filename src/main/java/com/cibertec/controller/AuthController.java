package com.cibertec.controller;


import com.cibertec.dto.AuthRequest;
import com.cibertec.dto.AuthResponse;
import com.cibertec.dto.RegisterRequest;
import com.cibertec.entity.User;
import com.cibertec.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody AuthRequest authRequest) {
        try {
            AuthResponse authResponse = authService.loginUser(authRequest);
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Error en la autenticación: " + e.getMessage());
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            User user = authService.registerUser(registerRequest);
            // Podrías devolver un mensaje más simple o el usuario creado (sin la contraseña)
            return ResponseEntity.ok("Usuario registrado exitosamente! Username: " + user.getUsername());
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // Endpoint de ejemplo para validar un token (podría estar en otro controller o ser interno)
    // Este endpoint necesitaría estar protegido por un filtro JWT si no fuera parte del flujo de Auth
    // @GetMapping("/validate")
    // public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String token) {
    //     if (token != null && token.startsWith("Bearer ")) {
    //         String jwt = token.substring(7);
    //         if (jwtUtil.validateToken(jwt)) {
    //             String username = jwtUtil.getUsernameFromToken(jwt);
    //             return ResponseEntity.ok("Token válido para usuario: " + username);
    //         }
    //     }
    //     return ResponseEntity.status(401).body("Token inválido o ausente.");
    // }
}