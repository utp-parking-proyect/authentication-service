package com.utp.authentication.service;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtService {

  private final JWKSource<SecurityContext> jwkSource;

  public String generateToken(UserDetails userDetails, Long userId) {
    Instant now = Instant.now();
    
    String roles = userDetails.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));

    JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("self")
        .issuedAt(now)
        .expiresAt(now.plus(1, ChronoUnit.HOURS))
        .subject(userDetails.getUsername())
        .claim("roles", roles)
        .claim("userId", userId)
        .build();

    JwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
    return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
  }
}
