package com.SystemAuth.loginSystem.repository;

import com.SystemAuth.loginSystem.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    boolean existsByUsername(String username);

    User findByUsername(String username);

    User findByEmail(String email);
}
