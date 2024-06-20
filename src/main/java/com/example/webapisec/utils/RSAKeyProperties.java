package com.example.webapisec.utils;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
public class RSAKeyProperties {
    private final RSAPublicKey rsaPublicKey;
    private final RSAPrivateKey rsaPrivateKey;

    public RSAKeyProperties() {
        KeyPair keyPair = KeyGeneratorUtil.generateRsaKey();
        this.rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        this.rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    }

    public RSAPublicKey getRsaPublicKey() {
        return rsaPublicKey;
    }

    public RSAPrivateKey getRsaPrivateKey() {
        return rsaPrivateKey;
    }
}
