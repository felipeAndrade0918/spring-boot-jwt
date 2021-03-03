package com.felipeandrade0918.springjwt.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api")
@RestController
public class SecurityController {

	@GetMapping("/protected")
	public String securityTest(@AuthenticationPrincipal Long userId) {
		return "I am protected, dear user " + userId;
	}
}
