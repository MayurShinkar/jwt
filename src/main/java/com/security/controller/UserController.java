package com.security.controller;

import java.security.Principal;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.model.User;
import com.security.model.UserRequest;
import com.security.model.UserResponse;
import com.security.serviceImpl.UserService;
import com.security.util.JwtUtil;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@RestController
@RequestMapping("/user")
public class UserController {

	@Autowired
	private UserService userService;
	
	@Autowired
	private JwtUtil util;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@PostMapping("/save")
	public ResponseEntity<String>saveUser(@RequestBody User user)
	{
		System.out.println("You are in controller");
		Integer id= userService.saveUser(user);
		String body="User '"+id+"' Saved Successfully";
		//return new ResponseEntity<>(body, HttpStatus.OK);
		return ResponseEntity.ok(body);
	}
	
	// Validate User and generate token
	@PostMapping("/login")
	public ResponseEntity<UserResponse> loginUser(@RequestBody UserRequest request)
	{
		//validate un/pwd with database
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
		
		String token=util.generateToken(request.getUsername());
		return ResponseEntity.ok(new UserResponse(token, "Success!"));	
	}
	
	// after login only
	@PostMapping("/welcome")
	public ResponseEntity<String> accessData(Principal p)
	{
		return ResponseEntity.ok("Hello "+ p.getName());
		
	}
	
	@GetMapping("/get")
	public ResponseEntity<List<User>> getUsers()
	{
	List<User>list=userService.getUsers();
		return ResponseEntity.ok(list);
	
	}
}

