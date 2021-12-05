package com.kononikhin.jwtTest;

import com.kononikhin.jwtTest.domain.models.AppUser;
import com.kononikhin.jwtTest.domain.models.Role;
import com.kononikhin.jwtTest.domain.services.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.ArrayList;

@SpringBootApplication
public class JwtTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtTestApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new AppUser(null, "John", "John", "123", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Bob", "Bob", "123", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Ivan", "Ivan", "123", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Danila", "Danila", "123", new ArrayList<>()));

            userService.addRoleToAppUser("John", "ROLE_USER");
            userService.addRoleToAppUser("Danila", "ROLE_SUPER_ADMIN");
            userService.addRoleToAppUser("Ivan", "ROLE_ADMIN");
            userService.addRoleToAppUser("Bob", "ROLE_USER");
            userService.addRoleToAppUser("Danila", "ROLE_ADMIN");
        };
    }

}
