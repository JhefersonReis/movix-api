package com.movix.api.controllers;

import com.movix.api.dto.auth.login.LoginRequestDTO;
import com.movix.api.dto.auth.register.RegisterRequestDTO;
import com.movix.api.dto.auth.register.RegisterResponseDTO;
import com.movix.api.entities.user.User;
import com.movix.api.infra.security.TokenService;
import com.movix.api.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequestDTO body) {
        Optional<User> optionalUser = userRepository.findByEmail(body.email());
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(401).body("Credenciais inválidas");
        }

        User user = optionalUser.get();

        if (!this.passwordEncoder.matches(body.password(), user.getPassword())) {
            return ResponseEntity.status(401).body("Credenciais inválidas");
        }

        String token = tokenService.generateToken(user);

        return ResponseEntity.ok(token);
    }

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody RegisterRequestDTO body) {
        Optional<User> userEmail = userRepository.findByEmail(body.email());
        if (userEmail.isPresent()) {
            return ResponseEntity.status(400).body("Email já cadastrado");
        }

        Optional<User> userCpf = userRepository.findByCpf(body.cpf());
        if (userCpf.isPresent()) {
            return ResponseEntity.status(400).body("CPF já cadastrado");
        }

        User newUser = new User();
        newUser.setPassword(passwordEncoder.encode(body.password()));
        newUser.setEmail(body.email());
        newUser.setName(body.name());
        newUser.setCpf(body.cpf());
        newUser.setPhone(body.phone());
        newUser.setRole(body.role());

        this.userRepository.save(newUser);

        String token = this.tokenService.generateToken(newUser);

        return ResponseEntity
                .ok(new RegisterResponseDTO(newUser.getName(), newUser.getEmail(), token));
    }
}
