package com.example.spring_boot_3_jwt_amigoscode;

import com.example.spring_boot_3_jwt_amigoscode.User.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);
}
