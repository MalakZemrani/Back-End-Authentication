package com.application.authentication.configuration;

import com.application.authentication.filter.JwtFilter;
import com.application.authentication.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.http.HttpHeaders.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtils jwtUtils;

    /**
     * Configures the security filter chain for handling HTTP requests.
     *
     * - Enables CORS with a custom configuration.
     * - Disables CSRF protection.
     * - Allows unauthenticated access to specific endpoints such as login, registration, roles and Swagger documentation.
     * - Requires authentication for all other endpoints.
     * - Adds a custom JWT filter to process JWT-based authentication.
     *
     * @param http the HttpSecurity object for configuring security settings.
     * @return the configured SecurityFilterChain.
     * @throws Exception if there is an error during configuration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/api/v1/login", "/api/v1/register", "/api/v1/roles",
                                        "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                                .anyRequest().authenticated())
                .addFilterBefore(new JwtFilter(customUserDetailsService, jwtUtils), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /**
     * Provides a password encoder for encoding and verifying passwords.
     *
     * @return a BCryptPasswordEncoder instance.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures the authentication manager with a custom user details service and password encoder.
     *
     * @param http           the HttpSecurity object for retrieving shared objects.
     * @param passwordEncoder the password encoder for verifying user credentials.
     * @return the configured AuthenticationManager.
     * @throws Exception if there is an error during configuration.
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, PasswordEncoder passwordEncoder) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder);
        return authenticationManagerBuilder.build();
    }

    /**
     * Configures the CORS (Cross-Origin Resource Sharing) settings to allow requests from specific origins.
     *
     * - Allows credentials to be included in requests.
     * - Restricts allowed origins to "http://localhost:4200".
     * - Specifies allowed headers such as `Authorization`, `Content-Type`, and others.
     * - Allows standard HTTP methods like GET and POST.
     * - Exposes specific headers like `Authorization` to the client.
     *
     * @return the configured CORS configuration source.
     */
    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        config.setAllowedHeaders(Arrays.asList(
                ORIGIN, CONTENT_TYPE, ACCEPT, AUTHORIZATION
        ));
        config.setAllowedMethods(Arrays.asList("GET", "POST"));
        config.addExposedHeader(AUTHORIZATION);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
