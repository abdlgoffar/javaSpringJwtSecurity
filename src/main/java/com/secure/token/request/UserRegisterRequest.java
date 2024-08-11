package com.secure.token.request;


import com.secure.token.entity.Role;
import lombok.Data;

@Data
public class UserRegisterRequest {


    private String username;
    private String password;
    private Role role;

}
