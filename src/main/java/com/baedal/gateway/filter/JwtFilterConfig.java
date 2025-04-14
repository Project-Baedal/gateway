package com.baedal.gateway.filter;

import lombok.Data;

@Data
public class JwtFilterConfig {
  private String headerName = "Authorization";
  private String granted = "Bearer";
}

