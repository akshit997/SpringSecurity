package com.example.security;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class MethodLevelSecurityController {
    
    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public String profile() {
        return "Profile : Only User and Above Roles can access this.";
    }

    @GetMapping("/manage")
    @PreAuthorize("hasRole('ADMIN')")
    public String manage() {
        return "Management : Only Admin Role can access this.";
    }

    @GetMapping("/claims/{id}")
    @PreAuthorize("#id == authentication.name or hasRole('ADMIN')")
    public String claims(@PathVariable String id) {
        //Example of SpEL using Security Context authentication object.
        return "Claims for user: " + id;
    }
}
