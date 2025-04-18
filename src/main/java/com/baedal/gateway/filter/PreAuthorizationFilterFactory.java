package com.baedal.gateway.filter;

import com.baedal.gateway.infrastructure.jwt.JwtProvider;
import com.baedal.gateway.infrastructure.jwt.JwtValidator;
import io.jsonwebtoken.JwtException;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class PreAuthorizationFilterFactory extends
    AbstractGatewayFilterFactory<JwtFilterConfig> {

  private final JwtValidator validator;

  private final JwtProvider provider;

  public PreAuthorizationFilterFactory(JwtValidator validator, JwtProvider provider) {
    super(JwtFilterConfig.class);
    this.validator = validator;
    this.provider = provider;
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
          validator.validateToken(token);

          ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
              .header("X-User-Id", provider.extractId(token).toString())
              .header("X-User-Role", provider.extractRole(token))
              .build();

          return chain.filter(exchange.mutate()
              .request(mutatedRequest)
              .build());
        } catch (JwtException e) {
          String exceptionClass = e.getClass().getName();
          String exceptionMessage = e.getMessage();

          String errorBody = String.format(
              "{ \"error\": \"%s\", \"message\": \"%s\" }",
              exceptionClass,
              exceptionMessage
          );

          exchange.getResponse()
              .getHeaders()
              .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
          exchange.getResponse()
              .setStatusCode(HttpStatus.UNAUTHORIZED);

          byte[] bytes = errorBody.getBytes(StandardCharsets.UTF_8);
          DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

          return exchange.getResponse()
              .writeWith(Mono.just(buffer))
              .doOnSuccess(v -> log.debug("Sent UNAUTHORIZED response"));
        }
      }

      exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
      return exchange.getResponse().setComplete();
    };
  }
}
