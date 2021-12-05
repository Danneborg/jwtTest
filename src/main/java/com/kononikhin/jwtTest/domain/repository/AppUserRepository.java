package com.kononikhin.jwtTest.domain.repository;

import com.kononikhin.jwtTest.domain.models.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    AppUser findByUserName(String userName);

}
