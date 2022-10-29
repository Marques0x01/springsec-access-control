package com.backend.backend.controllers;

import com.backend.backend.models.User;
import com.backend.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public User userModel(){
        return userRepository.findAll().get(0);
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public User userModel2(){
        return userRepository.findAll().get(1);
    }

    @GetMapping("/teste")
    @PreAuthorize("hasRole('ROLE_TESTE')")
    public User userModel3(){
        return userRepository.findAll().get(2);
    }

}
