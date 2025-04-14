package com.baedal.gateway.infrastructure.jwt;

import io.jsonwebtoken.Claims;
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
public class JwtCreator {

  private final SecretKey key;

  private final Long tokenExpirationSecond;

  public JwtCreator(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.expiration}") Long expiration) {
    this.key = new SecretKeySpec(
        secret.getBytes(StandardCharsets.UTF_8),
        Jwts.SIG.HS256.key().build().getAlgorithm());
    this.tokenExpirationSecond = expiration;
  }

  public String createToken(Long id, String email, String role) {
    Claims claims = Jwts.claims()
        .add("id", id)
        .add("email", email)
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
}
