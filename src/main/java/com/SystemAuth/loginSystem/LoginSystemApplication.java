package com.SystemAuth.loginSystem;

import com.SystemAuth.loginSystem.model.User;
import com.SystemAuth.loginSystem.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EntityScan("com.SystemAuth.loginSystem.model")
@EnableJpaRepositories(basePackages = "com.SystemAuth.loginSystem.repository")
public class LoginSystemApplication {
	public static void main(String[] args) throws Exception {

		SpringApplication.run(LoginSystemApplication.class, args);

	}

	@Bean
	CommandLineRunner initAdmin(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		return args -> {
			if (!userRepository.existsByUsername("admin")) {
				User admin = new User();
				admin.setUsername("admin");
				admin.setPassword(passwordEncoder.encode("Admin123!@#"));
				admin.setRole("ADMIN");
				userRepository.save(admin);
				System.out.println("Admin account created: username='admin', password='Admin123!@#'");
			}
		};
	}
}
