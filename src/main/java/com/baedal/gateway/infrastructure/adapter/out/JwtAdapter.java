package com.baedal.gateway.infrastructure.adapter.out;

import com.baedal.gateway.application.port.out.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtAdapter implements JwtTokenProvider {

  private final SecretKey key;

  private final Long tokenExpirationSecond;

  public JwtAdapter(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.expiration}") Long expiration) {
    this.key = new SecretKeySpec(
        secret.getBytes(StandardCharsets.UTF_8),
        Jwts.SIG.HS256.key().build().getAlgorithm());
    this.tokenExpirationSecond = expiration;
  }

  public String createToken(String email, String role) {
    Claims claims = Jwts.claims()
        .add("id", email)
        .add("role", role)
        .build();
    ZonedDateTime now = ZonedDateTime.now();
    ZonedDateTime expiration = now.plusSeconds(tokenExpirationSecond);

    return Jwts.builder()
        .claims(claims)
        .issuedAt(Date.from(now.toInstant()))
        .expiration(Date.from(expiration.toInstant()))
        .signWith(key)
        .compact();
  }

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
    } catch (JwtException | IllegalArgumentException exception) {
      log.debug(exception.getMessage());
      throw exception;
    }
  }
}
