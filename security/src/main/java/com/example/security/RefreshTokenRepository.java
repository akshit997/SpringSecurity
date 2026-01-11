package com.example.security;

import java.util.*;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
	Optional<RefreshTokenEntity> findByToken(String token);
	List<RefreshTokenEntity> findByUsernameAndRevokedFalse(String username);

}
