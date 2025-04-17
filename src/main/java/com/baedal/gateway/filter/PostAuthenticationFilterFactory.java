package com.baedal.gateway.filter;

import com.baedal.gateway.infrastructure.jwt.JwtCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class PostAuthenticationFilterFactory extends AbstractGatewayFilterFactory<JwtFilterConfig> {

  private final JwtCreator jwtCreator;

  private final ObjectMapper mapper;

  ModifyResponseBodyGatewayFilterFactory modifyFactory;

  public PostAuthenticationFilterFactory(JwtCreator jwtCreator, ObjectMapper mapper,
      ModifyResponseBodyGatewayFilterFactory modifyFactory) {
    super(JwtFilterConfig.class);
    this.jwtCreator = jwtCreator;
    this.mapper = mapper;
    this.modifyFactory = modifyFactory;
  }

  @Override
  public GatewayFilter apply(JwtFilterConfig config) {
    ModifyResponseBodyGatewayFilterFactory.Config innerConfig = new ModifyResponseBodyGatewayFilterFactory.Config();
    innerConfig.setInClass(String.class);
    innerConfig.setOutClass(String.class);
    innerConfig.setRewriteFunction(String.class, String.class, (exchange, body) -> {
      String path = exchange.getRequest().getURI().getPath();
      if (!path.endsWith("/login")) { // signup
        return Mono.justOrEmpty(body);
      }

      if (exchange.getResponse().getStatusCode() != HttpStatus.OK) {
        log.debug("로그인 실패 {}", exchange.getResponse().getStatusCode());
        return Mono.justOrEmpty(body);
      }

      try {
        Map<String, Object> response = mapper.readValue(body, Map.class);

        if (!response.containsKey("id")) {
          log.warn("로그인 응답으로 ID가 없음.");
          return Mono.justOrEmpty(body);
        }

        long id = ((Number) response.get("id")).longValue();

        String headerValue =
            config.getGranted() + " " + jwtCreator.createToken(id, config.getRole());

        exchange.getResponse().getHeaders().add(HttpHeaders.AUTHORIZATION, headerValue);

        return Mono.justOrEmpty(body);
      } catch (Exception e) {
        log.error(e.getClass().getName());
        log.error(e.getMessage());
        return Mono.error(new RuntimeException("JWT 생성 실패", e));
      }
    });

    return modifyFactory.apply(innerConfig);
  }
}
