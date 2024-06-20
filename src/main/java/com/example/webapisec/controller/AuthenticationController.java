package com.example.webapisec.controller;

import com.example.webapisec.dto.UserInfoDto;
import com.example.webapisec.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public Map<String, String> loginUser(@RequestBody UserInfoDto userInfoDto){
        String jwtToken = authenticationService.loginUser(userInfoDto.getUsername(), userInfoDto.getPassword());
        if (jwtToken != null) {
            return Map.of("success", "true",
                    "token", jwtToken);
        } else {
            return Map.of("success", "false");
        }
    }
}
