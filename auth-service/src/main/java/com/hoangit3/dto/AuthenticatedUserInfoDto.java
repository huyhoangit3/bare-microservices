package com.hoangit3.dto;

import lombok.Data;

import java.util.Set;

@Data
public class AuthenticatedUserInfoDto {
    private Long id;
    private String username;
    private Set<String> authorities;
}
