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

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String userModel(){
        return "ADMIN ON";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String userModel2(){
        return "USER ON";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('ROLE_MOD')")
    public String userModel3(){
        return "MOD ON";
    }

}
