package com.example.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
/*
Refresh Token Service Rotation and Reuse Detection
 */
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repo;
    private final long refreshExpDay;
    private final SecureRandom random = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository repo, @Value("${jwt.refresh-exp-days}") long refreshExpDay){
        this.repo=repo;
        this.refreshExpDay=refreshExpDay;
    }

    public RefreshTokenEntity createToken(String username, String userAgent, String ip){
        var now = Instant.now();
        var token = new RefreshTokenEntity();
        token.setToken(generateOpaqueToken());
        token.setUsername(username);
        token.setCreatedAt(now);
        token.setExpiresAt(now.plus(refreshExpDay, ChronoUnit.DAYS));
        token.setRevoked(false);
        token.setUserAgent(userAgent);
        token.setIp(ip);
        return repo.save(token);
    }

    public RefreshTokenEntity rotate(String oldTokenValue, String userAgent, String ip){
        var existing = repo.findByToken(oldTokenValue)
                .orElseThrow(()->new IllegalStateException("Invalid refresh token"));

        // Basic reuse detection: if already revoked, consider session compromised
        if(existing.isRevoked() || existing.getExpiresAt().isBefore(Instant.now())){
            revokeAllForUser(existing.getUsername());
            throw new IllegalStateException("Refresh token revoked or expired");
        }

        // Mark old as revoked and issue new
        existing.setRevoked(true);
        var newToken = createToken(existing.getUsername(), userAgent, ip);
        existing.setReplacedByToken(newToken.getToken());
        repo.save(existing);

        return newToken;
    }

    public void revoke(String tokenValue){
        repo.findByToken(tokenValue).ifPresent(t->{
            t.setRevoked(true);
            repo.save(t);
        });
    }

    public void revokeAllForUser(String username){
        var active = repo.findByUsernameAndRevokedFalse(username);
        active.forEach(t->{
            t.setRevoked(true);
        });
        repo.saveAll(active);
    }

    private String generateOpaqueToken(){
        //256-bit random, Base64URL without padding
        byte[] bytes= new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
