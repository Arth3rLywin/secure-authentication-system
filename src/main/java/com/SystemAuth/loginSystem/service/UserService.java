package com.SystemAuth.loginSystem.service;

import com.SystemAuth.loginSystem.model.User;
import com.SystemAuth.loginSystem.repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
public class UserService {

    @Value("${recaptcha.secret}")
    private String recaptchaSecret;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public boolean verifyRecaptcha(String gRecaptchaResponse) {

        if (gRecaptchaResponse == null || gRecaptchaResponse.isEmpty()) {
            return false;
        }

        String secret = recaptchaSecret;
        String url = "https://www.google.com/recaptcha/api/siteverify";

        try {
            RestTemplate restTemplate = new RestTemplate();

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("secret", secret);
            params.add("response", gRecaptchaResponse);

            Map<String, Object> googleResponse = restTemplate.postForObject(url, params, Map.class);

            if (googleResponse == null || googleResponse.isEmpty()) return false;

            Boolean success = (Boolean) googleResponse.get("success");
            return success != null && success;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public String register(String email, String username, String password, String confirmPassword, Model model) {

        if (!isValidEmail(email)) {
            return "Invalid email!";
        }

        if (username.isEmpty() || password.isEmpty() || confirmPassword.isEmpty())
            return "Username and passwords cannot be empty!";

        if (!password.equals(confirmPassword))
            return "Passwords do not match!";

        if (!isPasswordValid(password))
            return "Password does not meet security requirements!";

        if (userRepository.existsByUsername(username))
            return "Username already exists!";

        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        user.setDisplayName(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("USER");
        user.setProvider("local");

        GoogleAuthenticatorKey key = gAuth.createCredentials();
        user.setTotpSecret(key.getKey());

        userRepository.save(user);

        String totpUri = getTotpUri(username, key.getKey());

        String encodedTotpUri;
        try {
            encodedTotpUri = URLEncoder.encode(totpUri, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            encodedTotpUri = totpUri;
            e.printStackTrace();
        }

        String qrUrl = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + encodedTotpUri;
        System.out.println("QR URL: " + qrUrl);

        model.addAttribute("totpQrUrl", qrUrl);
        model.addAttribute("totpSecret", key.getKey());

        return "User registered successfully!";
    }

    public String getTotpUri(String username, String secret) {
        String issuer = "MyAuthApp";
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                issuer, username, secret, issuer
        );
    }

    public User authenticate(String username, String password) {
        User user = userRepository.findByUsername(username);
        if (user == null) return null;
        if (!passwordEncoder.matches(password, user.getPassword())) return null;
        System.out.println("Authentication: " + username);
        return user;
    }

    public boolean verifyTotp(User user, int code) {
        if (user.getTotpSecret() == null) return false;
        System.out.println("Verifying TOTP for" + user.getUsername() );
        return gAuth.authorize(user.getTotpSecret(), code);
    }

    private boolean isValidEmail(String email) {
        String regex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
        return email != null && email.matches(regex);
    }
    private boolean isPasswordValid(String password) {
        if (password == null || password.length() < 8 || password.length() > 64)
            return false;
        if (!password.matches(".*[A-Z].*")) return false;
        if (!password.matches(".*[a-z].*")) return false;
        if (!password.matches(".*\\d.*")) return false;
        if (!password.matches(".*[!@#$%^&*()_+\\-={}|\\[\\]:\";'<>?,./].*")) return false;
        if (password.matches(".*\\s.*")) return false;
        if (isGuessablePassword(password)) return false;
        return true;
    }

    private boolean isGuessablePassword(String password) {
        String[] blacklist = {"password", "123456", "qwerty", "admin", "letmein"};
        for (String bad : blacklist) {
            if (password.equalsIgnoreCase(bad)) return true;
        }
        return false;
    }
}
