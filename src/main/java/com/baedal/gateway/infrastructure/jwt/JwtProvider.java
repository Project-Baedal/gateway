package com.baedal.gateway.infrastructure.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtProvider {

  private final SecretKey key;
  private final Long tokenExpirationSecond;

  public JwtProvider(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.expiration}") Long expiration) {
    this.key = new SecretKeySpec(
        secret.getBytes(StandardCharsets.UTF_8),
        Jwts.SIG.HS256.key().build().getAlgorithm());
    this.tokenExpirationSecond = expiration;
  }

  public Long extractId(String token) {
    return parseClaims(token).getPayload()
        .get("id", Long.class);
  }

  public String extractRole(String token) {
    return parseClaims(token).getPayload()
        .get("role", String.class);
  }

  private Jws<Claims> parseClaims(String token) {
    return Jwts.parser()
        .verifyWith(key)
        .build()
        .parseSignedClaims(token);
  }
}

