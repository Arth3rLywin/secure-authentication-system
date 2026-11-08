package com.SystemAuth.loginSystem.controller;

import com.SystemAuth.loginSystem.model.User;
import com.SystemAuth.loginSystem.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

@Controller
public class DashboardController {

    private final UserRepository userRepository;

    public DashboardController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        String username = (String) session.getAttribute("username");
        String role = (String) session.getAttribute("role");
        String displayName = (String) session.getAttribute("displayName");

        if (username == null || role == null) {
            System.out.println("Dashboard accessed by " + username + " with the role: " + role);
            return "redirect:/auth/login";
        }

        String nameToShow = (displayName != null && !displayName.isEmpty()) ? displayName : username;

        model.addAttribute("username", username);
        model.addAttribute("role", role);
        model.addAttribute("displayName", nameToShow);

        if ("ADMIN".equals(role)) {
            List<User> users = userRepository.findAll();
            model.addAttribute("users", users);
            model.addAttribute("roles", role);
        }

        return "dashboard";
    }
}