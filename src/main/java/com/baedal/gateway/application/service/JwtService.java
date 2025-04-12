package com.baedal.gateway.application.service;

import com.baedal.gateway.domain.model.Role;
import com.baedal.gateway.infrastructure.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtService {

  private final JwtUtil util;

  public String createCustomerToken(String email) {
    return util.createToken(email, Role.CUSTOMER.getRole());
  }

  public String createOwnerToken(String email) {
    return util.createToken(email, Role.OWNER.getRole());
  }

  public String createRiderToken(String email) {
    return util.createToken(email, Role.RIDER.getRole());
  }

  public void validateToken(String token, String expectedRole) {
    util.validateToken(token, expectedRole);
  }
}
