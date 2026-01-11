package com.example.security;

import java.security.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final JpaUserDetailsService userDetailsService;

	public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, JpaUserDetailsService userDetailsService) {
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
		this.userDetailsService = userDetailsService;
	}

	@Bean
	public PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}

	/* JWT Related */
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider(){
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder());
		return provider;
	}

	/* JWT Related */
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config)throws Exception{
		return config.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http)throws Exception{
		http
		.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //JWT Stateless
		.authorizeHttpRequests(auth -> auth
			.requestMatchers("/h2-console/**").permitAll() // Must be first - allows H2 console
			.requestMatchers("/auth/**").permitAll() // JWT Auth endpoints
			.requestMatchers("/index").permitAll()
			.requestMatchers("/user").hasRole("USER")
			.requestMatchers("/admin").hasRole("ADMIN")
			.anyRequest().authenticated()
		)
		.csrf(csrf -> csrf.disable())
		.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin())) //allow h2-console to be displayed in a frame JPA Use case.
		.authenticationProvider(daoAuthenticationProvider()) // JWT Auth Provider
		.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // JWT Filter
		//.httpBasic(Customizer.withDefaults()); // removed for JWT		
		return http.build();
	}

}
