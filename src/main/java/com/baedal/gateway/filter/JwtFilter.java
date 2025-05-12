package com.baedal.gateway.filter;

import com.baedal.gateway.infrastructure.jwt.JwtProvider;
import com.baedal.gateway.infrastructure.jwt.JwtValidator;
import io.jsonwebtoken.JwtException;
import java.nio.charset.StandardCharsets;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter implements GlobalFilter, Ordered {

  private final JwtValidator validator;

  private final JwtProvider provider;

  @Value("${jwt.headerName}")
  private String headerName;

  @Value("${jwt.granted}")
  private String granted;

  @Value("${jwt.loginUrlEndsWith}")
  private String loginUrl;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String path = exchange.getRequest().getURI().getPath();
    log.debug("routing...{}", path);

    String token = extractToken(exchange.getRequest());
    if (token == null) {
      return chain.filter(exchange);
    }

    try {
      validator.validateToken(token);

      ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
          .header("X-User-Id", provider.extractId(token).toString())
          .header("X-User-Role", provider.extractRole(token))
          .build();

      return chain.filter(exchange.mutate()
          .request(mutatedRequest)
          .build());
    } catch (JwtException | IllegalArgumentException e) {
      log.debug(e.getMessage());
      return unauthorizedResponse(exchange.getResponse());
    }
  }

  private String extractToken(HttpRequest request) {
    String header = request.getHeaders().getFirst(headerName);
    if (StringUtils.hasText(header) &&
        header.startsWith(granted + " ")) {
      return header.substring(granted.length() + 1);
    }
    return null;
  }

  private Mono<Void> unauthorizedResponse(ServerHttpResponse response) {
    response.setStatusCode(HttpStatus.UNAUTHORIZED);

    response.getHeaders()
        .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
    String errorBody = "{ \"error\": \"UNAUTHORIZED\", \"message\": \"Missing or invalid Authorization header\" }";

    byte[] bytes = errorBody.getBytes(StandardCharsets.UTF_8);
    DataBuffer buffer = response.bufferFactory().wrap(bytes);
    return response.writeWith(Mono.just(buffer));
  }

  @Override
  public int getOrder() {
    return -1;
  }
}
