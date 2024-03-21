package com.example.webapisec.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin("*")
public class ApiController {

    @GetMapping("/foo")
    public Map<String, Object> foo() {
        return Map.of("body", "foo");
    }

    @GetMapping("/bar")
    public Map<String, Object> bar() {
        return Map.of("body", "bar");
    }
}
