package com.example.authserver.repositories;

import com.example.authserver.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    // @Query let repository method to execute SQL
    @Query("SELECT u from User u WHERE u.email = :email")
    Optional<User> findByUsername(String email);
}
