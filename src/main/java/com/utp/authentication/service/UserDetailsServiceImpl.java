package com.utp.authentication.service;

import com.utp.authentication.model.dto.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  private final WebClient.Builder webClient;

  @Override
  @NullMarked
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    log.debug("Attempting to load user: {}", username);
    Map<String, String> params = new HashMap<>();
    params.put("username", username);
    try {
      User user = webClient.build()
          .get()
          .uri("/username/{username}", params)
          .retrieve()
          .bodyToMono(User.class)
          .block();
      if (user == null) {
        log.error("User returned null from users-service: {}", username);
        throw new UsernameNotFoundException("User not found: " + username);
      }

      log.debug("User loaded successfully: {}", user.getUsername());
      log.debug("User roles: {}", user.getRoles());

      List<GrantedAuthority> roles = user.getRoles().stream()
          .map(role -> (GrantedAuthority) role::getName)
          .toList();
      return new org.springframework.security.core.userdetails.User(user.getUsername(),
          user.getPassword(),
          user.getActualRegistered(),
          true,
          true,
          true,
          roles);
    } catch (WebClientResponseException e) {
      log.error("WebClient error loading user {}: Status={}, Body={}",
          username, e.getStatusCode(), e.getResponseBodyAsString());
      throw new UsernameNotFoundException("User not found: " + username);
    } catch (Exception e) {
      log.error("Error loading user {}: {}", username, e.getMessage(), e);
      throw new UsernameNotFoundException("Error loading user: " + username + " - " + e.getMessage());
    }
  }
}