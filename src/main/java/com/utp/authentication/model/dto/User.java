package com.utp.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class User {
  private Long idUser;
  private String username;
  private String password;
  private String name;
  private String lastname;
  private String dni;
  private String institutionalEmail;
  private String career;
  private Boolean actualRegistered;
  private List<Role> roles;
  private CampusDto campus;
}
