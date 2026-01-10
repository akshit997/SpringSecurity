package com.example.security;

import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {
    
    @Bean
    CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByUsername("dbuser").isEmpty()) {
                UserEntity user = new UserEntity();
                user.setUsername("dbuser");
                user.setPassword(passwordEncoder.encode("password"));
                user.setAuthorities(Set.of("ROLE_USER"));
                userRepository.save(user);
            }

            if (userRepository.findByUsername("dbadmin").isEmpty()) {
                UserEntity admin = new UserEntity();
                admin.setUsername("dbadmin");
                admin.setPassword(passwordEncoder.encode("admin123"));
                admin.setAuthorities(Set.of("ROLE_ADMIN"));
                userRepository.save(admin);
            }
        };
    }
}
