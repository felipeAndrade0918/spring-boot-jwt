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

import com.felipeandrade0918.springjwt.config.security.JwtService;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	private JwtService jwtService;
	
	public AuthorizationFilter(AuthenticationManager authenticationManager, JwtService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String authorizationHeader = request.getHeader("Authorization");
		
		if (authorizationHeader != null) {
			Long userId = Long.valueOf(jwtService.retrieveSubject(authorizationHeader));
			
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
			SecurityContextHolder.getContext().setAuthentication(token);
		}
		
		chain.doFilter(request, response);
	}
}
