package com.example.webapisec;

import com.example.webapisec.utils.KeyGeneratorUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    @Test
    public void generateRSAKey() throws NoSuchAlgorithmException, IOException {
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKey();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        // 保存公钥到文件
        saveKeyToFile("publicKey.pem", rsaPublicKey);

        // 保存私钥到文件
        saveKeyToFile("privateKey.pem", rsaPrivateKey);
    }

    private static void saveKeyToFile(String fileName, Serializable key) throws IOException {
        FileOutputStream fos = new FileOutputStream(fileName);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(key);
        oos.close();
    }

    @Test
    public void readKeyFromFile() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // 读取公钥文件
        FileInputStream fisPublicKey = new FileInputStream("publicKey.pem");
        byte[] encodedPublicKey = new byte[fisPublicKey.available()];
        fisPublicKey.read(encodedPublicKey);
        fisPublicKey.close();

        // 读取私钥文件
        FileInputStream fisPrivateKey = new FileInputStream("privateKey.pem");
        byte[] encodedPrivateKey = new byte[fisPrivateKey.available()];
        fisPrivateKey.read(encodedPrivateKey);
        fisPrivateKey.close();

        // 解析公钥
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));

        // 解析私钥
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));

        // 使用公钥和私钥进行后续操作...

        System.out.println(publicKey);
        System.out.println("----------------------------------------");
        System.out.println(privateKey);
    }

}
