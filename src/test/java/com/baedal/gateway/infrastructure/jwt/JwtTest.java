package com.baedal.gateway.infrastructure.jwt;

import com.baedal.gateway.domain.model.Role;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTest {

  final String key = "my-local-secret-key-should-be-long-enough";
  final long expiration = 1800L;

  @Autowired
  JwtCreator jwtCreator = new JwtCreator(key, expiration);

  @Autowired
  JwtValidator jwtValidator = new JwtValidator(key, expiration);

  @Test
  void create_and_validate_token_success() {
    String token = jwtCreator.createToken(1L, Role.CUSTOMER.getRole());

    assertThatCode(() -> jwtValidator.validateToken(token))
        .doesNotThrowAnyException();
  }

  @Test
  void validate_token_fail_TOKEN_STRANGE() {
    String token = "asd.adfadfa.eee";

    assertThatThrownBy(() -> jwtValidator.validateToken(token))
        .isInstanceOf(JwtException.class);
  }
}