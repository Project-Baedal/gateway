package com.baedal.gateway.infrastructure.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtValidator {

  private final SecretKey key;

  private final Long tokenExpirationSecond;

  public JwtValidator(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.expiration}") Long expiration) {
    this.key = new SecretKeySpec(
        secret.getBytes(StandardCharsets.UTF_8),
        Jwts.SIG.HS256.key().build().getAlgorithm());
    this.tokenExpirationSecond = expiration;
  }

  // TODO: Exception 발생 및 처리
  public void validateToken(String token, String expectedRole) {
    try {
      Jws<Claims> jwsClaims = Jwts.parser()
          .verifyWith(key)
          .build()
          .parseSignedClaims(token);

      Date expiration = jwsClaims.getPayload().getExpiration();
      if (expiration.before(new Date())) {
        throw new RuntimeException("Token Expired");
      }

      String role = jwsClaims.getPayload().get("role", String.class);
      if (!role.equals(expectedRole)) {
        throw new RuntimeException("Unauthorized");
      }
    } catch (JwtException exception) {
      log.debug(exception.getMessage());
      throw exception;
    }
  }
}
