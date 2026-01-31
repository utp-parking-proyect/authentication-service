package com.utp.authentication.controller;

import com.utp.authentication.model.dto.AuthenticationRequest;
import com.utp.authentication.model.dto.AuthenticationResponse;
import com.utp.authentication.model.dto.User;
import com.utp.authentication.service.JwtService;
import com.utp.authentication.util.constants.Constants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AuthenticationController {

  private final AuthenticationManager authenticationManager;
  private final JwtService jwtService;
  private final WebClient.Builder webClient;

  @PostMapping("/authenticate")
  public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
    log.info("Authentication attempt for user: {}", request.getUsername());
    try {
      Authentication authentication = authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(
              request.getUsername(),
              request.getPassword()
          )
      );

      log.info("User authenticated successfully: {}", request.getUsername());

      UserDetails userDetails = (UserDetails) authentication.getPrincipal();

      Map<String, String> params = new HashMap<>();
      params.put("username", request.getUsername());

      log.debug("Fetching user details from users-service for: {}", request.getUsername());
      User user = webClient.build()
          .get()
          .uri("/username/{username}", params)
          .retrieve()
          .bodyToMono(User.class)
          .block();

      if (user != null) {
        log.debug("User details fetched successfully. UserId: {}", user.getIdUser());
      } else {
        log.warn("User details returned null from users-service");
      }

      String token = jwtService.generateToken(userDetails, user != null ? user.getIdUser() : null);
      log.info("JWT token generated successfully for user: {}", request.getUsername());

      AuthenticationResponse response = new AuthenticationResponse(
          token,
          userDetails.getUsername(),
          user != null ? user.getIdUser() : null
      );

      return ResponseEntity.ok(response);

    } catch (BadCredentialsException e) {
      log.error("Bad credentials for user: {}", request.getUsername());
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of(Constants.ERROR_VALUE, "Credenciales inválidas"));
    } catch (Exception e) {
      log.error("Authentication error for user {}: {}", request.getUsername(), e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(Map.of(Constants.ERROR_VALUE, "Error en la autenticación: " + e.getMessage()));
    }
  }

  @GetMapping("/validate")
  public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
    try {
      if (authHeader != null && authHeader.startsWith("Bearer ")) {
        String token = authHeader.substring(7);
        return ResponseEntity.ok(Map.of(Constants.VALID_VALUE, true, "token", token));
      }
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of(Constants.VALID_VALUE, false, Constants.ERROR_VALUE, "Token no proporcionado"));
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of(Constants.VALID_VALUE, false, Constants.ERROR_VALUE, e.getMessage()));
    }
  }
}
