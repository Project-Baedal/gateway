package com.baedal.gateway.application.port.in;

public interface JwtUseCase {

  String createCustomerToken(String email);

  String createOwnerToken(String email);

  String createRiderToken(String email);

  void validateToken(String token, String expectedRole);
}
