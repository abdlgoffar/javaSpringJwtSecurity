package com.secure.token.response;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserLoginResponse {

    private String jwtToken;
    private String username;
    private List<String> roles;

}
