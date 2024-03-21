package com.example.webapisec;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Date;

@SpringBootTest
class WebapiSecApplicationTests {

    @Test
    void contextLoads() {
        SecretKey secretKey = Keys.hmacShaKeyFor("keykeykeykeykeykeykeykeykeykeykeykeykeykeykey".getBytes(StandardCharsets.UTF_8));

        String compact = Jwts.builder()
                .header()
                .add("typ", "JWT")
//                .add("alg", "HS256")
                .and()
                .claims()
                .id("1")
                .issuedAt(new Date())
                .subject("jwttest")
                .issuer("Chan")
                .and()
                .claim("username", "user")
                .signWith(secretKey,
                        Jwts.SIG.HS256)
                .compact();
        System.out.println(compact);


    }

    @Test
    public void test2() {
        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxIiwiaWF0IjoxNzA4MzA4MzgzLCJzdWIiOiJqd3R0ZXN0IiwiaXNzIjoiQ2hhbiIsInVzZXJuYW1lIjoidXNlciJ9.-MYAobPBaDzbFyrDzC1ZrYi4h2uPjRYnN3LSB23mVPI";

        SecretKey secretKey = Keys.hmacShaKeyFor("keykeykeykeykeykeykeykeykeykeykeykeykeykeykey".getBytes(StandardCharsets.UTF_8));

        Jws<Claims> claimsJws = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(jwtStr);

        Claims payload = claimsJws.getPayload();
        System.out.println(payload.getId());
        System.out.println(payload.getIssuer());
        System.out.println(payload.getIssuedAt());
        System.out.println(payload.get("username"));
    }

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void encode() {
        System.out.println(passwordEncoder.encode("Aa1"));
    }

}
