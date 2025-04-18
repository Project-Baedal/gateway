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
  //  -ExpiredJwtException : JWT를 생성할 때 지정한 유효기간 초과할 때.
  //  -UnsupportedJwtException : 예상하는 형식과 일치하지 않는 특정 형식이나 구성의 JWT일 때
  //  -MalformedJwtException : JWT가 올바르게 구성되지 않았을 때
  //  -SignatureException :  JWT의 기존 서명을 확인하지 못했을 때
  public void validateToken(String token) {
    try {
      Jws<Claims> jwsClaims = Jwts.parser()
          .verifyWith(key)
          .build()
          .parseSignedClaims(token);

      Date expiration = jwsClaims.getPayload().getExpiration();
      if (expiration.before(new Date())) {
        throw new RuntimeException("Token Expired");
      }
    } catch (JwtException exception) {
      log.debug(exception.getMessage());
      throw exception;
    }
  }
}
