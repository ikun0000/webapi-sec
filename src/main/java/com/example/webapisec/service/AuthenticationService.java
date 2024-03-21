package com.example.webapisec.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private AuthenticationManager authenticationManager;
    private TokenService tokenService;

    @Autowired
    public AuthenticationService(AuthenticationManager authenticationManager, TokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    public String loginUser(String username, String password) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            String jwtToken = tokenService.generateJwt(authentication);
            return jwtToken;
        } catch (AuthenticationException e) {
            return null;
        }
    }
}
