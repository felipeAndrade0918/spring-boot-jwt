package com.felipeandrade0918.springjwt.config.security.filter;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	private String jwtSecret;
	
	public AuthorizationFilter(AuthenticationManager authenticationManager, String jwtSecret) {
		super(authenticationManager);
		this.jwtSecret = jwtSecret;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String authorizationHeader = request.getHeader("Authorization");
		
		if (authorizationHeader != null) {
			Long userId = Long.valueOf(JWT.require(Algorithm.HMAC256(jwtSecret))
			.build()
			.verify(authorizationHeader.replace("Bearer ", ""))
			.getSubject());
			
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
			SecurityContextHolder.getContext().setAuthentication(token);
		}
		
		chain.doFilter(request, response);
	}
}
