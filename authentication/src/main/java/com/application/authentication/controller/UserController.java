package com.application.authentication.controller;

import com.application.authentication.DTO.LoginUserRequest;
import com.application.authentication.DTO.RegisterUserRequest;
import com.application.authentication.configuration.JwtUtils;
import com.application.authentication.entity.Role;
import com.application.authentication.entity.User;
import com.application.authentication.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "User API", description = "API for user management")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    /**
     * Registers a new user with a specified role.
     *
     * @param registerRequest contains the username, password, and role for the new user.
     * @return a ResponseEntity containing the registered user or an error message if the username already exists or fields are missing.
     */
    @PostMapping("/register")
    @Operation(summary = "Create a new user", description = "Registers a new user with a specific role.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User successfully created"),
            @ApiResponse(responseCode = "400", description = "Username already exists")
    })
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterUserRequest registerRequest) {

        if (registerRequest.getUsername() == null || registerRequest.getUsername().isEmpty() ||
                registerRequest.getPassword() == null || registerRequest.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body(createErrorResponse("Please fill in both username and password"));
        }

        if (userRepository.findByUsername(registerRequest.getUsername()) != null) {
            return ResponseEntity.badRequest().body(createErrorResponse("Username already exists"));
        }
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setRole(registerRequest.getRole());

        return ResponseEntity.ok(userRepository.save(user));
    }

    /**
     * Authenticates a user with their username and password.
     *
     * @param loginRequest contains the username and password for authentication.
     * @return a ResponseEntity containing the JWT token if authentication succeeds, or an error message if it fails.
     */
    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticates a user with their username and password.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "401", description = "Invalid username or password")
    })
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginUserRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
            if (authentication.isAuthenticated()) {
                User user = userRepository.findByUsername(loginRequest.getUsername());
                Map<String, Object> authData = new HashMap<>();
                authData.put("token", jwtUtils.generateToken(loginRequest.getUsername(),user.getRole()));
                authData.put("type", "Bearer");
                return ResponseEntity.ok(authData);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("Invalid username or password"));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(createErrorResponse("Invalid username or password"));
        }

    }

    /**
     * Retrieves the list of available user roles.
     *
     * @return a ResponseEntity containing a list of all roles.
     */
    @GetMapping("/roles")
    public ResponseEntity<List<String>> getRoles() {
        List<String> roles = Arrays.stream(Role.values())
                .map(Enum::name)
                .collect(Collectors.toList());
        return ResponseEntity.ok(roles);
    }

    /**
     * Creates a response format for errors.
     *
     * @param message the error message to include.
     * @return a Map containing the error details.
     */
    private Map<String, String> createErrorResponse(String message) {
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("errorMsg", message);
        return errorResponse;
    }
}