package com.SystemAuth.loginSystem;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import org.json.JSONObject;

public class TokenUtil {

    private static final SecretKey AES_KEY = loadAesKey();
    private static final SecretKey HMAC_KEY = loadHmacKey();

    private static SecretKey loadAesKey() {
        String base64Key = System.getenv("AES_SECRET_KEY");
        if (base64Key == null || base64Key.isEmpty()) {
            throw new IllegalStateException("AES_SECRET_KEY is not set");
        }

        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("AES key must be 32 bytes for AES-256");
        }

        return new SecretKeySpec(keyBytes, "AES");
    }

    private static SecretKey loadHmacKey() {
        String base64Key = System.getenv("HMAC_SECRET_KEY");
        if (base64Key == null || base64Key.isEmpty()) {
            throw new IllegalStateException("HMAC_SECRET_KEY is not set");
        }

        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    public static String generateToken(String username,String role, long expiryEpochSeconds) throws Exception {
        JSONObject payload = new JSONObject();
        payload.put("sub", username);
        payload.put("role", role);
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("exp", expiryEpochSeconds);

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, AES_KEY, ivSpec);
        byte[] encrypted = cipher.doFinal(payload.toString().getBytes());

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(HMAC_KEY);
        byte[] signature = mac.doFinal(encrypted);

        return Base64.getEncoder().encodeToString(signature) + "." +
                Base64.getEncoder().encodeToString(iv) + "." +
                Base64.getEncoder().encodeToString(encrypted);
    }

    public static JSONObject validateToken(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new SecurityException("Invalid token format");

        byte[] signature = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] encrypted = Base64.getDecoder().decode(parts[2]);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(HMAC_KEY);
        byte[] expectedSig = mac.doFinal(encrypted);
        if (!MessageDigest.isEqual(signature, expectedSig)) {
            throw new SecurityException("Invalid token signature");
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, AES_KEY, new IvParameterSpec(iv));
        String json = new String(cipher.doFinal(encrypted));

        JSONObject payload = new JSONObject(json);
        long exp = payload.getLong("exp");
        if (Instant.now().getEpochSecond() > exp) {
            throw new SecurityException("Token expired");
        }

        return payload;
    }

}