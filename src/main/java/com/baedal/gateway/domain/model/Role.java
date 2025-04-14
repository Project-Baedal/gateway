package com.baedal.gateway.domain.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum Role {

  CUSTOMER("ROLE_CUSTOMER"),
  OWNER("ROLE_OWNER"),
  RIDER("ROLE_RIDER");

  private final String role;
}
