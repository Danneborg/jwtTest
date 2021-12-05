package com.kononikhin.jwtTest.domain.services;

import com.kononikhin.jwtTest.domain.models.AppUser;
import com.kononikhin.jwtTest.domain.models.Role;
import com.kononikhin.jwtTest.domain.repository.AppUserRepository;
import com.kononikhin.jwtTest.domain.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AppUserServiceImpl implements UserService, UserDetailsService {

    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public AppUser saveUser(AppUser appUser) {
        log.info("Saving user {} to the DB", appUser.getName());
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return appUserRepository.save(appUser);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving role {} to the DB", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToAppUser(String userName, String roleName) {
        log.info("Adding role {} to the user {}", roleName, userName);
        AppUser appUser = appUserRepository.findByUserName(userName);
        Role role = roleRepository.findByName(roleName);
        appUser.getRoles().add(role);
    }

    @Override
    public AppUser getAppUser(String userName) {
        log.info("Fetching user {} from the DB", userName);
        return appUserRepository.findByUserName(userName);
    }

    @Override
    public List<AppUser> getUsers() {
        log.info("Fetching all users from the DB");
        return appUserRepository.findAll();
    }

    @Override
    public List<Role> getRoles() {
        log.info("Fetching all roles from the DB");
        return roleRepository.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = appUserRepository.findByUserName(username);
        if (appUser == null) {
            log.error("User {} not found in the DB", username);
            throw new UsernameNotFoundException(String.format("User not found %s in the DB", username));
        } else {
            log.info("User {} found in the DB", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        appUser.getRoles().forEach(e -> authorities.add(new SimpleGrantedAuthority(e.getName())));
        return new org.springframework.security.core.userdetails.User(appUser.getName(), appUser.getPassword(), authorities);
    }
}
