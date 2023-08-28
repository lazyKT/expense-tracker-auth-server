package com.example.authserver.services;

import com.example.authserver.entities.User;
import com.example.authserver.model.SecurityUser;
import com.example.authserver.repositories.UserRepository;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * This class is for authentication of the users.
 * By defining this class (implementing UserDetailsService)
 * we can remove UserDetailsService() class from security config
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(UserRepository repository) {
        this.userRepository = repository;
    }


    // Tip! UsernameNotFoundException is the RuntimeException, so even if we remove it, the program will compile
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.printf("loadUserByUsername::username::%s\n", username);
        Optional<User> user = userRepository.findByUsername(username);
        return user.map(SecurityUser::new).orElseThrow(() -> new UsernameNotFoundException(":("));
    }
}
