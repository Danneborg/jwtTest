package com.kononikhin.jwtTest.domain.services;

import com.kononikhin.jwtTest.domain.models.AppUser;
import com.kononikhin.jwtTest.domain.models.Role;

import java.util.List;

public interface UserService {

    AppUser saveUser(AppUser appUser);

    Role saveRole(Role role);

    void addRoleToAppUser(String userName, String roleName);

    AppUser getAppUser(String userName);

    List<AppUser> getUsers();

    List<Role> getRoles();

}
