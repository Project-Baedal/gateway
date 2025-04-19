package com.baedal.gateway.filter;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtFilterConfig {

  private String headerName = "Authorization";
  private String granted = "Bearer";
  private String role;
}

