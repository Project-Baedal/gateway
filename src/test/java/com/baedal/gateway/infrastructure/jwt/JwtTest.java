package com.baedal.gateway.infrastructure.jwt;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.baedal.gateway.domain.model.Role;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class JwtTest {

  final String key = "my-local-secret-key-should-be-long-enough";
  final long expiration = 1800L;

  @Autowired
  JwtCreator jwtCreator = new JwtCreator(key, expiration);

  @Autowired
  JwtValidator jwtValidator = new JwtValidator(key, expiration);

  @Test
  void create_and_validate_token_success() {
    String token = jwtCreator.createToken(1L, "example@gmail.com", Role.CUSTOMER.getRole());

    assertThatCode(() -> jwtValidator.validateToken(token, Role.CUSTOMER.getRole()))
        .doesNotThrowAnyException();
  }

  @Test
  void validate_token_fail_UNAUTHORIEZED_WRONG_ROLE() {
    String token = jwtCreator.createToken(1L, "example@gmail.com", Role.CUSTOMER.getRole());

    assertThatThrownBy(() -> jwtValidator.validateToken(token, Role.RIDER.getRole()))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void validate_token_fail_TOKEN_STRANGE() {
    String token = "asd.adfadfa.eee";

    assertThatThrownBy(() -> jwtValidator.validateToken(token, Role.CUSTOMER.getRole()))
        .isInstanceOf(JwtException.class);
  }
}