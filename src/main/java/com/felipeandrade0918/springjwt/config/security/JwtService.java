package com.felipeandrade0918.springjwt.config.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.felipeandrade0918.springjwt.model.User;

@Service
public class JwtService {

	@Value("${jwt.secret}")
	private String jwtSecret;
	
	@Value("${jwt.expiration-in-milliseconds}")
	private Long expirationTime;
	
	public String createToken(User user) {
		return JWT.create()
				.withSubject(user.getId().toString())
				.withClaim("username", user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + expirationTime))
				.sign(Algorithm.HMAC256(jwtSecret));
	}
	
	public String retrieveSubject(String authorizationHeader) {
		return JWT.require(Algorithm.HMAC256(jwtSecret))
		.build()
		.verify(authorizationHeader.replace("Bearer ", ""))
		.getSubject();
	}
}
