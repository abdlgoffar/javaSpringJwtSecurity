package com.secure.token.controller;



import com.secure.token.component.jwt.JwtUtils;
import com.secure.token.request.UserLoginRequest;
import com.secure.token.request.UserRegisterRequest;
import com.secure.token.response.UserLoginResponse;
import com.secure.token.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AppController {
    @Autowired
    private UserService userService;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;
    @GetMapping(
            path = "v1/api/all"
    )
    public String all() {
        return  "This is All Controller";
    }
    @PostMapping(
            path = "v1/api/register",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public String UserRegister(@RequestBody UserRegisterRequest request) {
        userService.UserRegister(request);
        return  "Oke";
    }
    @PostMapping(
            path = "v1/api/login",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Object> UserLogin(@RequestBody UserLoginRequest request) {
//        Check Auth User
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

//        Get Authenticated User
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

//        If Authenticated Create Jwt Token
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

//        Get Role User
        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());

//        Create Response Data
        UserLoginResponse response = new UserLoginResponse( jwtToken, userDetails.getUsername(), roles);

        return ResponseEntity.ok(response);
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping(
            path = "v1/api/admin"
    )
    public String admin() {
        return  "This is Admin Controller";
    }
    @PreAuthorize("hasRole('USER')")
    @GetMapping(
            path = "v1/api/user"
    )
    public String user() {
        return  "This is User Controller";
    }
}
