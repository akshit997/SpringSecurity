package com.example.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    
    private final SecretKey key;
//  private final long jwtExpirationInMillis;
    private final long accessExpMillis;

    public JwtService(
        @Value("${jwt.secret}") String secret,
        @Value("${jwt.access-exp-minutes}") long accessExpMillis) {
            this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            this.accessExpMillis = accessExpMillis * 60_000L;     
    }   

    public String generateToken(UserDetails user){
        var now = Instant.now();
        var claims = Map.<String, Object>of("roles", user.getAuthorities().stream().map
        (a->a.getAuthority()).toArray(String[]::new));

        return Jwts.builder()
            .setSubject(user.getUsername())
            .addClaims(claims)
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(now.plusMillis(accessExpMillis)))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }

    public String extractUserName(String token){
        return parseClaims(token).getBody().getSubject();
    }

    public List<String> extractRoles(String token){
        var body = parseClaims(token).getBody();
        Object roles = body.get("roles");
        if(roles instanceof List<?> list){
            return list.stream().map(Object::toString).toList();
    } else if(roles instanceof String s){
            return List.of(s);
    } else if(roles instanceof String[] arr){
            return List.of(arr);
    }
        return List.of();
    }
    
    public boolean isTokenValid(String token, UserDetails user){
        try
        {
            var username = extractUserName(token);
            var exp = parseClaims(token).getBody().getExpiration();
            return username.equals(user.getUsername()) && exp.after(new Date());
        } 
        catch (JwtException | IllegalArgumentException e)
        {
            return false;
        }
    }

    private Jws<Claims> parseClaims(String token){
        return Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token);
    }

}
