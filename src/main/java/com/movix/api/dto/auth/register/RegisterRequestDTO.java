package com.movix.api.dto.auth.register;

import com.movix.api.domain.user.UserRole;

public record RegisterRequestDTO(String name, String email, String password, String cpf, String phone, UserRole role) {
}
