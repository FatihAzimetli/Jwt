package com.tpe.repository;

import com.tpe.domain.User;
import com.tpe.exception.ResourceNotFoundException;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserName(String userName) throws ResourceNotFoundException;
    boolean existsByUserName(String userName);
}
