package com.kononikhin.jwtTest.domain.repository;

import com.kononikhin.jwtTest.domain.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
