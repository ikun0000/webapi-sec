package com.example.webapisec.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/user")
@CrossOrigin("*")
public class UserController {

    @GetMapping("/info")
    public Map<String, String> info() {
        return Map.of("user", "info");
    }
}
