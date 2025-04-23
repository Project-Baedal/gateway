package com.baedal.gateway.exception;

import java.util.Map;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;

@Component
public class GlobalErrorAttributes extends DefaultErrorAttributes {

  @Override
  public Map<String, Object> getErrorAttributes(ServerRequest request,
      ErrorAttributeOptions options) {
    Throwable error = getError(request);

    Map<String, Object> attributes = super.getErrorAttributes(request, options);
    attributes.put("exception", error.getClass().getName());
    attributes.put("message", error.getMessage());

    return attributes;
  }
}
