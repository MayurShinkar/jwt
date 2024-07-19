package com.security.service;

import java.util.List;
import java.util.Optional;

import com.security.model.User;

public interface IUserService {

	Integer saveUser(User user);
	Optional<User> findByUsername(String username);
	public  List<User> getUsers();
}
