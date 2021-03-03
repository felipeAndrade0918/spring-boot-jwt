package com.felipeandrade0918.springjwt.config.security.filter;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.felipeandrade0918.springjwt.dto.LoginRequest;
import com.felipeandrade0918.springjwt.model.User;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private String jwtSecret;
	
	public AuthenticationFilter(AuthenticationManager authenticationManager, String jwtSecret) {
		setAuthenticationManager(authenticationManager);
		this.jwtSecret = jwtSecret;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		try {
			LoginRequest loginRequest = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);

			return getAuthenticationManager()
					.authenticate(
							new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
							);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		User user = (User) authResult.getPrincipal();
		
		String token = JWT.create()
		.withSubject(user.getId().toString())
		.withClaim("email", user.getUsername())
		.withExpiresAt(new Date(System.currentTimeMillis() + 20_000))
		.sign(Algorithm.HMAC256(jwtSecret));
		
		response.getWriter().write(token);
		response.getWriter().flush();
	}
}
