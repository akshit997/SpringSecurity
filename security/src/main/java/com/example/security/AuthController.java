package com.example.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

record LoginRequest(String username, String password) {}
record AuthResponse(String accessToken, String refreshToken, String tokenType, long expiresInSeconds) {}
record RefreshRequest(String refreshToken){}

@RestController
@RequestMapping("/auth" )
public class AuthController {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshService;

    private final String cookieDomain;
    private final boolean cookieSecure;
    private final String cookieSameSite;


    public AuthController(AuthenticationManager authenticationManager,
                          UserDetailsService userDetailsService,
                          JwtService jwtService,
                          RefreshTokenService refreshService,
                          @Value("${security.cookies.domain}") String cookieDomain,
                          @Value("${security.cookies.secure}") boolean cookieSecure,
                          @Value("${security.cookies.same-site}") String cookieSameSite)
    {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.refreshService = refreshService;
        this.cookieDomain = cookieDomain;
        this.cookieSecure = cookieSecure;
        this.cookieSameSite = cookieSameSite;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest req, HttpServletRequest request){
        //Authenticate User Credentials
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(req.username(), req.password()));
        //Load User and Generate JWT Token  
        var userDetails = userDetailsService.loadUserByUsername(req.username());
        var token = jwtService.generateToken(userDetails);

        RefreshTokenEntity rt= refreshService.createToken(
                userDetails.getUsername(), request.getHeader("User-Agent"), request.getRemoteAddr());

        //Demo Return refresh in the body AND set cookie
        var cookie = builderRefreshCookie(rt.getToken(), Duration.ofDays(7));
        return ResponseEntity.ok()
                .header("Set-Cookie", cookie.toString())
                .body(new AuthResponse(token, rt.getToken(), "Bearer", 15*60));

    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody RefreshRequest req, HttpServletRequest request){

        RefreshTokenEntity newRT = refreshService.rotate(
                req.refreshToken(), request.getHeader("User-Agent"), request.getRemoteAddr());

        var user = userDetailsService.loadUserByUsername(newRT.getUsername());
        String accessToken = jwtService.generateToken(user);

        var cookie = builderRefreshCookie(newRT.getToken(), Duration.ofDays(7));
        return ResponseEntity.ok()
                .header("Set-Cookie", cookie.toString())
                .body(new AuthResponse(accessToken, newRT.getToken(), "Bearer", 15*60));

    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshRequest req){
        // revoke provided refresh token (you can also revoke all the user)
        refreshService.revoke(req.refreshToken());
        //set expired cookie
        var cookie = builderRefreshCookie("", Duration.ZERO);
        return ResponseEntity.noContent()
                .header("Set-Cookie", cookie.toString())
                .build();
    }

    private ResponseCookie builderRefreshCookie(String value, Duration maxAge){
        return ResponseCookie.from("refreshToken", value)
                .httpOnly(true)
                .secure(cookieSecure)
                .domain(cookieDomain)
                .path("/auth")
                .sameSite(cookieSameSite)
                .maxAge(maxAge)
                .build();
    }
    
}
