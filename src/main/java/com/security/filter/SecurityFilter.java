package com.security.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.util.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class SecurityFilter extends OncePerRequestFilter{
	
	@Autowired
	private JwtUtil util;
	
	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, 
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		//Read token from authorization header
		String token=request.getHeader("Authorization");
		if(token!=null)
		{
			//do validation
			String username=util.getUsername(token);
			//username should not be empty & context Auth must be empty
			if(username!=null && 
					SecurityContextHolder.getContext()
					.getAuthentication()==null)
			{
				//load User from Database
				UserDetails usr=userDetailsService.loadUserByUsername(username);
				
				//validate token
				boolean isValid=util.validateToken(token, usr.getUsername());
				if(isValid)
				{
					UsernamePasswordAuthenticationToken authToken=
							new UsernamePasswordAuthenticationToken(username, usr.getPassword(),usr.getAuthorities());
					authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					
					//final object stored in security context with userdetails(un,pwd)
					SecurityContextHolder.getContext().setAuthentication(authToken);
				}
			}
		}
		filterChain.doFilter(request, response);
	}

}
