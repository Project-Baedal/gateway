package com.baedal.gateway.application.port.out;

public interface JwtTokenProvider {

  String createToken(String email, String role);

  void validateToken(String token, String expectedRole);
}
