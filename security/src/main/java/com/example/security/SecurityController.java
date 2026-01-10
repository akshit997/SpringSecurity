package com.example.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {
	
	@GetMapping("/index")
	public String myindex() {
		return "Spring Security 6 is in Action";
	}
	@GetMapping("/user")
	public String myuser() {
		return "Spring Security 6 is in Action with User Role";
	}
	@GetMapping("/admin")
	public String myadmin() {
		return "Spring Security 6 is in Action with Admin Role";
	}

}
