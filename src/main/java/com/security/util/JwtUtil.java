package com.security.util;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

	//method no 1 and 6 are must to write
	
		@Value("${app.secret}")
		private String secret;
		
		// 6 Validate token username & Database username and expiry date
		public boolean validateToken(String token, String username)
		{
			String tokenUsername=getUsername(token);
			return (username.equals(tokenUsername)&& !isTokenExpired(token));
			
		}
		
		// 5 Validate Expiry Date
		public boolean isTokenExpired(String token)
		{
			Date expDate=getExpiryDate(token);
			return expDate.before(new Date(System.currentTimeMillis()));
		}
		
		// 4 Read Subject/Username
		public String getUsername(String token)
		{
			return getclaims(token).getSubject();
			
		}
		
		// 3 Read Expiry Date
		public Date getExpiryDate(String token)
		{
			return getclaims(token).getExpiration();
			
		}
		
		// 2 Read Claims or Token Data
		public Claims getclaims(String token)
		{
			return Jwts.parser()
					.setSigningKey(secret.getBytes())
					.parseClaimsJws(token)
					.getBody();
			
		}
		
		
		// 1 Generate Token
		public String generateToken(String subject)
		{
			return Jwts.builder()
					.setSubject(subject)
					.setIssuer("Neosoft")
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(60)))
					.signWith(SignatureAlgorithm.HS512, secret.getBytes())
					.compact();
			
		}

}
