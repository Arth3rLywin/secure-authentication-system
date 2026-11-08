package com.SystemAuth.loginSystem.controller;

import com.SystemAuth.loginSystem.TokenUtil;
import com.SystemAuth.loginSystem.model.User;
import com.SystemAuth.loginSystem.repository.UserRepository;
import com.SystemAuth.loginSystem.service.EmailService;
import com.SystemAuth.loginSystem.service.UserService;
import jakarta.servlet.http.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Random;

@Controller
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String email,
                           @RequestParam String username,
                           @RequestParam String password,
                           @RequestParam String confirmPassword,
                           Model model) {

        String msg = userService.register(email, username, password, confirmPassword, model);

        if (msg.equals("User registered successfully!")) {
            model.addAttribute("message", msg);
            return "register-totp";
        } else {
            model.addAttribute("error", msg);
            return "register";
        }
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        @RequestParam("g-recaptcha-response") String gRecaptchaResponse,
                        @RequestParam(required = false) String totp,
                        HttpSession session,
                        HttpServletResponse response,
                        Model model) throws Exception {

        User user = userService.authenticate(username, password);
        if (user == null) {
            model.addAttribute("error", "Invalid username or password");
            return "login";
        }

        if (gRecaptchaResponse == null || !userService.verifyRecaptcha(gRecaptchaResponse)) {
            model.addAttribute("error", "Captcha verification failed. Are you a robot?");
            return "login";
        }

        if (user.getTotpSecret() != null) {
            if (totp == null || totp.isEmpty()) {
                model.addAttribute("totpRequired", true);
                model.addAttribute("username", username);
                model.addAttribute("password", password);

                return "login";
            }

            try {
                String cleanedTotp = totp.trim();
                if (cleanedTotp.length() != 6 || !cleanedTotp.matches("\\d{6}")) {
                    throw new NumberFormatException("TOTP must be 6 digits");
                }

                int totpCode = Integer.parseInt(cleanedTotp);
                if (!userService.verifyTotp(user, totpCode)) {
                    model.addAttribute("error", "Invalid verification code");
                    model.addAttribute("totpRequired", true);
                    model.addAttribute("username", username);
                    model.addAttribute("password", password);
                    return "login";
                }
            } catch (NumberFormatException e) {
                model.addAttribute("error", "Invalid verification code format");
                model.addAttribute("totpRequired", true);
                model.addAttribute("username", username);
                model.addAttribute("password", password);
                return "login";
            }
        }

        session.setAttribute("username", user.getUsername());
        session.setAttribute("role", user.getRole());

        long expiry = Instant.now().plusSeconds(60).getEpochSecond();
        String token = TokenUtil.generateToken(user.getUsername(),user.getRole(), expiry);

        Cookie jwtCookie = new Cookie("auth_token", token);

        jwtCookie.setHttpOnly(true);
        jwtCookie.setSecure(false);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(60);
        response.addCookie(jwtCookie);

        System.out.println("✅ Login successful for user: " + user.getUsername());
        System.out.println("Generated token for user:" +token);

        model.addAttribute("token", token);
        return "TokenDisplay";
    }

    @GetMapping("/TokenDisplay")
    public String showToken (HttpServletRequest request, Model model) {
        String token = (String) request.getAttribute("token");
        model.addAttribute("token", token != null ? token : "No token found!");
        return "TokenDisplay";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/auth/login?logout";
    }

    @GetMapping("/forget-password")
    public String forgetPassword () {
        return "forget-password";
    }

    @PostMapping("/send-otp")
    public String sendOtp(@RequestParam String email, HttpSession session, Model model) {
        String otp = String.valueOf(new Random().nextInt(900000) + 100000);
        emailService.sendOTP(email, otp);
        session.setAttribute("otp", otp);
        session.setAttribute("otpEmail", email);
        model.addAttribute("message", "OTP sent to your email.");
        return "verify-otp";
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String otp, HttpSession session, Model model) {
        String sessionOtp = (String) session.getAttribute("otp");

        if (sessionOtp != null && sessionOtp.equals(otp)) {
            model.addAttribute("message", "OTP Verified! You can reset the password now.");
            return "reset-password";
        } else {
            model.addAttribute("error", "Invalid OTP");
            return "verify-otp";
        }
    }

    @PostMapping("/reset-password")
    public String resetPassword(@RequestParam String newPassword,
                                @RequestParam String confirmPassword,
                                HttpSession session,
                                Model model) {
        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match.");
            return "reset-password";
        }

        String email = (String) session.getAttribute("otpEmail");
        if (email == null) {
            model.addAttribute("error", "Session expired. Please restart the process.");
            return "forget-password";
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            model.addAttribute("error", "User not found.");
            return "forget-password";
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        session.removeAttribute("otp");
        session.removeAttribute("otpEmail");

        model.addAttribute("message", "Password reset successful. You can now log in.");
        return "login";
    }

    @GetMapping("/register-totp")
    public String showTotpSetup(@RequestParam String username, Model model) {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            model.addAttribute("error", "User not found.");
            return "login";
        }

        String totpUri = userService.getTotpUri(user.getUsername(), user.getTotpSecret());
        String encodedUri = URLEncoder.encode(totpUri, StandardCharsets.UTF_8);
        String qrUrl = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + encodedUri;

        model.addAttribute("totpQrUrl", qrUrl);
        model.addAttribute("totpSecret", user.getTotpSecret());
        return "register-totp";
    }
}