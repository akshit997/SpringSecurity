package com.example.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

record LoginRequest(String username, String password) {}
record AuthResponse(String accessToken, String tokenType, long expiresInSeconds) {}

@RestController
@RequestMapping("/auth" )
public class AuthController {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;

    public AuthController(JwtService jwtService, UserDetailsService userDetailsService, AuthenticationManager authenticationManager)
    {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest req){
        //Authenticate User Credentials
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(req.username(), req.password()));
        //Load User and Generate JWT Token  
        var userDetails = userDetailsService.loadUserByUsername(req.username());
        var token = jwtService.generateToken(userDetails);

        return new AuthResponse(token, "Bearer", 60);
    }


    
    
}
