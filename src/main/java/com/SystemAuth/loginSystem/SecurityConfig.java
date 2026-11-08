package com.SystemAuth.loginSystem;

import com.SystemAuth.loginSystem.model.User;
import com.SystemAuth.loginSystem.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class SecurityConfig {

    private final UserRepository userRepository;

    public SecurityConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(customizer ->
                customizer.additionalParameters(params -> params.put("prompt", "select_account"))
        );

        http
                .csrf().disable()
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**", "/login**", "/dashboard**", "/forget-password**",
                                "/verify-otp**", "/reset-password**", "/css/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.disable())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/auth/login")
                        .authorizationEndpoint(endpoint ->
                                endpoint.authorizationRequestResolver(resolver))
                        .userInfoEndpoint(userInfo ->
                                userInfo.userService(this.oauth2UserService()))
                        .successHandler((request, response, authentication) -> {
                            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
                            String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();

                            String email = oAuth2User.getAttribute("email");
                            String name = oAuth2User.getAttribute("name");

                            if ("github".equals(registrationId)) {
                                String githubUsername = oAuth2User.getAttribute("login");

                                if (email == null && githubUsername != null) {
                                    email = githubUsername + "@github.com";
                                }

                                if (email != null) {
                                    User user = userRepository.findByUsername(email);
                                    if (user == null) {
                                        user = new User();
                                        user.setUsername(email);
                                        user.setEmail(email);
                                        user.setDisplayName(name != null ? name : githubUsername);
                                        user.setPassword(passwordEncoder().encode("github"));
                                        user.setRole("USER");
                                        user.setProvider("github");
                                        user.setTotpSecret(null);
                                        user.setCreatedAt(LocalDateTime.now());
                                        userRepository.save(user);
                                    }

                                    HttpSession session = request.getSession();
                                    session.setAttribute("username", user.getUsername());
                                    session.setAttribute("role", user.getRole());
                                    session.setAttribute("displayName", user.getDisplayName());

                                    long expiry = Instant.now().plusSeconds(180).getEpochSecond();
                                    String token = null;
                                    try {
                                        token = TokenUtil.generateToken(user.getUsername(),user.getRole(), expiry);
                                    } catch (Exception e) {
                                        throw new RuntimeException(e);
                                    }

                                    Cookie authCookie = new Cookie("auth_token", token);
                                    authCookie.setHttpOnly(true);
                                    authCookie.setSecure(true);
                                    authCookie.setPath("/");
                                    authCookie.setMaxAge(180);
                                    response.addCookie(authCookie);

                                    request.setAttribute("token", token);
                                }
                            } else if (email != null) {
                                User user = userRepository.findByUsername(email);
                                if (user == null) {
                                    user = new User();
                                    user.setUsername(email);
                                    user.setEmail(email);
                                    user.setDisplayName(name);
                                    user.setPassword(passwordEncoder().encode("google"));
                                    user.setRole("USER");
                                    user.setProvider("google");
                                    user.setTotpSecret(null);
                                    user.setCreatedAt(LocalDateTime.now());
                                    userRepository.save(user);
                                }

                                HttpSession session = request.getSession();
                                session.setAttribute("username", user.getUsername());
                                session.setAttribute("role", user.getRole());
                                session.setAttribute("displayName", user.getDisplayName());

                                long expiry = Instant.now().plusSeconds(60).getEpochSecond();
                                String token = null;
                                try {
                                    token = TokenUtil.generateToken(user.getUsername(),user.getRole(), expiry);
                                } catch (Exception e) {
                                    throw new RuntimeException(e);
                                }

                                Cookie authCookie = new Cookie("auth_token", token);
                                authCookie.setHttpOnly(true);
                                authCookie.setSecure(true);
                                authCookie.setPath("/");
                                authCookie.setMaxAge(180);
                                response.addCookie(authCookie);

                                request.setAttribute("token", token);
                            }

                            request.getRequestDispatcher("/auth/TokenDisplay").forward(request, response);
                        })
                )
                .logout(logout -> logout
                        .logoutUrl("/auth/logout")
                        .logoutSuccessUrl("/auth/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private DefaultOAuth2UserService oauth2UserService() {
        return new DefaultOAuth2UserService() {
            @Override
            public OAuth2User loadUser(OAuth2UserRequest userRequest) {
                OAuth2User user = super.loadUser(userRequest);
                Map<String, Object> attributes = new HashMap<>(user.getAttributes());
                String registrationId = userRequest.getClientRegistration().getRegistrationId();
                attributes.put("registrationId", registrationId);

                String nameAttributeKey = "email";
                if ("github".equals(registrationId)) {
                    nameAttributeKey = "login";
                }
                return new DefaultOAuth2User(user.getAuthorities(), attributes, nameAttributeKey);
                }
            };
        }
    }