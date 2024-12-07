package com.application.authentication.DTO;

import com.application.authentication.entity.Role;
import lombok.Data;

@Data
public class RegisterUserRequest {
    private String username;
    private String password;
    private Role role;
}
