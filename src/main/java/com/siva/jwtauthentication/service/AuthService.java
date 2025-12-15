package com.siva.jwtauthentication.service;

import com.siva.jwtauthentication.dto.LoginRequest;
import com.siva.jwtauthentication.dto.LoginResponse;
import com.siva.jwtauthentication.dto.RefreshTokenRequest;
import com.siva.jwtauthentication.dto.RegisterRequest;
import com.siva.jwtauthentication.model.AppUser;
import com.siva.jwtauthentication.repository.AppUserRepository;
import com.siva.jwtauthentication.security.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AppUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(AppUserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public void register(RegisterRequest request){

        if(userRepository.existsByUsername(request.getUsername())){
            throw new IllegalArgumentException("Username already in use");
        }

        String pwHash = passwordEncoder.encode(request.getPassword());
        AppUser user = new AppUser(request.getUsername(), pwHash, "USER");

        userRepository.save(user);

    }

    public LoginResponse login(LoginRequest request){
        AppUser user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        if(!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())){
            throw new IllegalArgumentException("Invalid credentials");
        }

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return new LoginResponse(
                user.getId(),
                user.getUsername(),
                accessToken,
                refreshToken
        );
    }

    public LoginResponse refreshTokens(RefreshTokenRequest request){
        String refreshToken = request.getRefreshToken();

        if(!jwtService.isTokenValid(refreshToken) || !jwtService.isRefreshToken(refreshToken)){
            throw new IllegalArgumentException("Invalid refresh token");
        }

        Long userId = jwtService.extractuserId(refreshToken);
        AppUser user =  userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        return new LoginResponse(
                user.getId(),
                user.getUsername(),
                newAccessToken,
                newRefreshToken
        );
    }

}
