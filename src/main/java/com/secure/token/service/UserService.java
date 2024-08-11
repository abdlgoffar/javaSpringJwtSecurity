package com.secure.token.service;


import com.secure.token.entity.User;
import com.secure.token.repository.UserRepository;
import com.secure.token.request.UserRegisterRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isEmpty()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username Or Password Not Found");
        return user.get();
    }
    public void UserRegister(UserRegisterRequest request) {
        Optional<User> data = userRepository.findByUsername(request.getUsername());
        if (data.isPresent()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username Or Password Is Available");

        User user = new User();
        user.setUsername(request.getUsername());
        String encode = bCryptPasswordEncoder.encode(request.getPassword());
        user.setPassword(encode);
        user.setRole(request.getRole());

        userRepository.save(user);
    }
}
