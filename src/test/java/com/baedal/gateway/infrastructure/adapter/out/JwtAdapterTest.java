package com.baedal.gateway.infrastructure.adapter.out;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.baedal.gateway.domain.model.Role;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class JwtAdapterTest {

  @Autowired
  JwtAdapter jwtAdapter = new JwtAdapter("my-local-secret-key-should-be-long-enough", 1800L);

  @Test
  void create_and_validate_token_success() {
    String token = jwtAdapter.createToken("example@gmail.com", Role.CUSTOMER.getRole());

    assertThatCode(() -> jwtAdapter.validateToken(token, Role.CUSTOMER.getRole()))
        .doesNotThrowAnyException();
  }

  @Test
  void validate_token_fail_UNAUTHORIEZED_WRONG_ROLE() {
    String token = jwtAdapter.createToken("example@gmail.com", Role.CUSTOMER.getRole());

    assertThatThrownBy(() -> jwtAdapter.validateToken(token, Role.RIDER.getRole()))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  void validate_token_fail_TOKEN_STRANGE() {
    String token = "asd.adfadfa.eee";

    assertThatThrownBy(() -> jwtAdapter.validateToken(token, Role.CUSTOMER.getRole()))
        .isInstanceOf(JwtException.class);
  }
}