package com.siva.jwtauthentication.security;

import com.siva.jwtauthentication.model.AppUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private final Key signingKey;
    private final long accessTokenExpirationMs;
    private final long refreshTokenExpirationMs;

    public JwtService(@Value("${app.jwt.secret}") String secret, @Value("${app.jwt.access-expiration-ms}") long accessTokenExpirationMs, @Value("${app.jwt.refresh-expiration-ms}") long refreshTokenExpirationMs) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    public String generateAccessToken(AppUser user){
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("role", user.getRole());
        return buildToken(claims, user.getUsername(), accessTokenExpirationMs);
    }

    public String generateRefreshToken(AppUser user){
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("type","refresh");
        return buildToken(claims, user.getUsername(), refreshTokenExpirationMs);
    }

    private String buildToken(Map<String, Object> claims, String subject, long expirationMs){
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token){
        try{
            parseAllClaims(token);
            return true;
        }catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }

    public Claims parseAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    public Long extractuserId(String token){
        Claims claims = parseAllClaims(token);
        Object value = claims.get("userId");
        return value == null ? null : Long.valueOf(value.toString());
    }

    public boolean isRefreshToken(String token){
        Claims claims = parseAllClaims(token);
        Object type = claims.get("type");
        return "refresh".equals(type);
    }

}
