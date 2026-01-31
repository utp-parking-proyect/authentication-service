package com.utp.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
  private String token;
  private String type = "Bearer";
  private String username;
  private Long userId;
  
  public AuthenticationResponse(String token, String username, Long userId) {
    this.token = token;
    this.type = "Bearer";
    this.username = username;
    this.userId = userId;
  }
}
