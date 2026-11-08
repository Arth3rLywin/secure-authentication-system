package com.SystemAuth.loginSystem;

import javax.crypto.SecretKey;
import java.util.Base64;

public class KeyGenerator {
    public static boolean generateKeys() throws Exception {
        javax.crypto.KeyGenerator aesGen = javax.crypto.KeyGenerator.getInstance("AES");
        aesGen.init(256);
        SecretKey aesKey = aesGen.generateKey();
        System.out.println("AES Key (Base64): " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

        javax.crypto.KeyGenerator hmacGen = javax.crypto.KeyGenerator.getInstance("HmacSHA256");
        hmacGen.init(256);
        SecretKey hmacKey = hmacGen.generateKey();
        System.out.println("HMAC Key (Base64): " + Base64.getEncoder().encodeToString(hmacKey.getEncoded()));
        return false;
    }
}
