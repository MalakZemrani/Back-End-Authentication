package com.application.authentication.DTO;

import lombok.Data;

@Data
public class LoginUserRequest {
    private String username;
    private String password;
}
