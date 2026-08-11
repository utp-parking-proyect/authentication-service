package com.utp.authentication.service;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.utp.authentication.util.constants.Constants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

  private JwtService jwtService;

  @BeforeEach
  void setUp() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
        .privateKey((RSAPrivateKey) keyPair.getPrivate())
        .keyID(UUID.randomUUID().toString())
        .build();

    JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
    jwtService = new JwtService(jwkSource);
  }

  private SignedJWT parse(String token) throws ParseException {
    return SignedJWT.parse(token);
  }

  @Test
  void generateToken_carriesUsernameRolesAndUserId() throws Exception {
    UserDetails userDetails = new User("jdoe", "hash",
        List.of(new SimpleGrantedAuthority("ROLE_STUDENT")));

    SignedJWT jwt = parse(jwtService.generateToken(userDetails, 10L));

    assertEquals("jdoe", jwt.getJWTClaimsSet().getSubject());
    assertEquals(List.of("ROLE_STUDENT"), jwt.getJWTClaimsSet().getClaim(Constants.CLAIM_ROLES));
    assertEquals(10L, ((Number) jwt.getJWTClaimsSet().getClaim(Constants.CLAIM_USER_ID)).longValue());
  }

  @Test
  void generateServiceToken_carriesTheInternalServiceAuthorityAndNoUser() throws Exception {
    SignedJWT jwt = parse(jwtService.generateServiceToken());

    assertEquals(Constants.SERVICE_SUBJECT, jwt.getJWTClaimsSet().getSubject());
    assertEquals(List.of(Constants.ROLE_INTERNAL_SERVICE),
        jwt.getJWTClaimsSet().getClaim(Constants.CLAIM_ROLES));
    assertNull(jwt.getJWTClaimsSet().getClaim(Constants.CLAIM_USER_ID));
  }

  @Test
  void generateServiceToken_isShortLived() throws Exception {
    SignedJWT jwt = parse(jwtService.generateServiceToken());

    long lifetimeSeconds = (jwt.getJWTClaimsSet().getExpirationTime().getTime()
        - jwt.getJWTClaimsSet().getIssueTime().getTime()) / 1000;

    assertEquals(Constants.SERVICE_TOKEN_TTL_SECONDS, lifetimeSeconds);
    assertTrue(lifetimeSeconds < 300);
  }
}
