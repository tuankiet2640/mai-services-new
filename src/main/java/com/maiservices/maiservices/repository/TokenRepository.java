package com.maiservices.maiservices.repository;

import com.maiservices.maiservices.entity.Token;
import com.maiservices.maiservices.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    @Query("SELECT t FROM Token t WHERE t.user.id = :userId AND (t.expired = false OR t.revoked = false)")
    List<Token> findAllValidTokensByUser(UUID userId);
    
    Optional<Token> findByToken(String token);
    
    List<Token> findAllByUser(User user);
}
