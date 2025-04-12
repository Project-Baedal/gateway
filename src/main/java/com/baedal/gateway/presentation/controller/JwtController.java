package com.baedal.gateway.presentation.controller;

import com.baedal.gateway.application.port.in.JwtUseCase;
import com.baedal.gateway.presentation.request.CreateTokenRequest;
import com.baedal.gateway.presentation.response.CreateTokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class JwtController {

  private final JwtUseCase useCase;

  // FIXME: 어떤 protocol로 jwt 생성 요청을 제공할지?
  //  - gRPC, http, etc...
  @PostMapping("/api/tokens")
  public ResponseEntity<CreateTokenResponse> createToken(@RequestBody CreateTokenRequest request) {
    String token = useCase.createCustomerToken(request.email());
    return ResponseEntity.ok(new CreateTokenResponse(token));
  }
}
