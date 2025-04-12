package com.baedal.gateway.application.service;

import com.baedal.gateway.application.port.in.JwtUseCase;
import com.baedal.gateway.application.port.out.JwtTokenProvider;
import com.baedal.gateway.domain.model.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtService implements JwtUseCase {

  private final JwtTokenProvider jwtTokenProvider;

  public String createCustomerToken(String email) {
    return jwtTokenProvider.createToken(email, Role.CUSTOMER.getRole());
  }

  public String createOwnerToken(String email) {
    return jwtTokenProvider.createToken(email, Role.OWNER.getRole());
  }

  public String createRiderToken(String email) {
    return jwtTokenProvider.createToken(email, Role.RIDER.getRole());
  }

  public void validateToken(String token, String expectedRole) {
    jwtTokenProvider.validateToken(token, expectedRole);
  }
}
