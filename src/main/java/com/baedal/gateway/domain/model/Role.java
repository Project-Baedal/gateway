package com.baedal.gateway.domain.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum Role {

  CUSTOMER("CUSTOMER"),
  OWNER("OWNER"),
  RIDER("RIDER");

  private final String role;
}
