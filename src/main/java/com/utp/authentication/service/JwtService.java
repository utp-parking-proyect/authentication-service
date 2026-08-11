package com.utp.authentication.service;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.utp.authentication.util.constants.Constants;
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
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtService {

  private final JWKSource<SecurityContext> jwkSource;

  public String generateToken(UserDetails userDetails, Long userId) {
    Instant now = Instant.now();

    List<String> roles = userDetails.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toList();

    JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("self")
        .issuedAt(now)
        .expiresAt(now.plus(1, ChronoUnit.HOURS))
        .subject(userDetails.getUsername())
        .claim(Constants.CLAIM_ROLES, roles)
        .claim(Constants.CLAIM_USER_ID, userId)
        .build();

    return encode(claims);
  }

  public String generateServiceToken() {
    Instant now = Instant.now();

    JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer("self")
        .issuedAt(now)
        .expiresAt(now.plusSeconds(Constants.SERVICE_TOKEN_TTL_SECONDS))
        .subject(Constants.SERVICE_SUBJECT)
        .claim(Constants.CLAIM_ROLES, List.of(Constants.ROLE_INTERNAL_SERVICE))
        .build();

    return encode(claims);
  }

  private String encode(JwtClaimsSet claims) {
    JwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
    return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
  }
}
