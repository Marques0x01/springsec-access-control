package com.backend.backend.repositories;

import com.backend.backend.models.RefreshToken;
import com.backend.backend.models.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    Optional<RefreshToken> findByToken(String token);

    Boolean existsByUser(User user);

    int deleteByUser(User user);
}
