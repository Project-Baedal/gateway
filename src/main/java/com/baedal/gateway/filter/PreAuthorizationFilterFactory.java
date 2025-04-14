package com.baedal.gateway.filter;

import com.baedal.gateway.domain.model.Role;
import com.baedal.gateway.infrastructure.jwt.JwtValidator;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@Slf4j
public class PreAuthorizationFilterFactory extends
    AbstractGatewayFilterFactory<JwtFilterConfig> {

  private final JwtValidator validator;

  public PreAuthorizationFilterFactory(JwtValidator validator) {
    super(JwtFilterConfig.class);
    this.validator = validator;
  }

  @Override
  public GatewayFilter apply(JwtFilterConfig config) {
    return (exchange, chain) -> {
      String path = exchange.getRequest().getURI().getPath();

      if (path.endsWith("/login") || path.endsWith("/signup")) {
        return chain.filter(exchange);
      }

      String authorizationHeader = exchange.getRequest().getHeaders()
          .getFirst(config.getHeaderName());
      if (StringUtils.hasText(authorizationHeader) &&
          authorizationHeader.startsWith(config.getGranted() + " ")) {
        String token = authorizationHeader.substring(config.getGranted().length() + 1); // Bearer

        try {
          // TODO: 각 회원 별 role 검증은 어떻게 할까?
          //  - /api/domain/** domain 마다의 role 검증.
          validator.validateToken(token, config.getRole());
          log.debug("JWT 검증 성공");
          return chain.filter(exchange);
        } catch (JwtException e) {
          log.error("JWT 검증 실패: {}", e.getMessage());
        }
      }

      log.debug("UNAUTHORIZED authorization={}", authorizationHeader);
      exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
      return exchange.getResponse().setComplete();
    };
  }
}
