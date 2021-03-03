package com.felipeandrade0918.springjwt.config.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.felipeandrade0918.springjwt.config.security.JwtService;
import com.felipeandrade0918.springjwt.dto.LoginRequest;
import com.felipeandrade0918.springjwt.model.User;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private JwtService jwtService;
	
	public AuthenticationFilter(AuthenticationManager authenticationManager, JwtService jwtService) {
		setAuthenticationManager(authenticationManager);
		this.jwtService = jwtService;
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
		
		String token = jwtService.createToken(user);
		
		response.getWriter().write(token);
		response.getWriter().flush();
	}
}
