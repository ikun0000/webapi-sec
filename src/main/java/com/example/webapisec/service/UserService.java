package com.example.webapisec.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class UserService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // DO YOUR SELF

        if (username.equals("user")) {
            return new User("user", "$2a$10$dWHIR3ggSj5mpxRG8P/r1uYVkt2mN8i9qEot/sO8IHbxf99eqHf4m",
                    Arrays.asList(new SimpleGrantedAuthority("USER")));
        } else if (username.equals("admin")) {
            return new User("admin", "$2a$10$dWHIR3ggSj5mpxRG8P/r1uYVkt2mN8i9qEot/sO8IHbxf99eqHf4m",
                    Arrays.asList(new SimpleGrantedAuthority("ADMIN")));
        } else {
            throw new UsernameNotFoundException(username + " does not found!");
        }
    }
}
