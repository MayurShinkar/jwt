package com.security.serviceImpl;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.security.model.User;
import com.security.repository.UserRepository;
import com.security.service.IUserService;

@Service
public class UserService implements IUserService,UserDetailsService{
	
	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private BCryptPasswordEncoder encodePwd;

	@Override
	public Integer saveUser(User user) {
		//Encode password
		user.setPassword(encodePwd.encode(user.getPassword()));
		//save user
		return userRepo.save(user).getId();
	}

	// get user by username
	@Override
	public Optional<User> findByUsername(String username) {
		
		return userRepo.findByUsername(username);
	}
      //-------------------------------------------------------------

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> op=findByUsername(username);
		if(op.isEmpty())
			throw new UsernameNotFoundException("User Not Exists!");
		User user=op.get();
		return new org.springframework.security.core.userdetails.User(username, 
				user.getPassword(),
				user.getRoles().stream().map(role-> new SimpleGrantedAuthority(role)).collect(Collectors.toList()));
	}

	@Override
	public List<User> getUsers() {
		
		return userRepo.findAll();
	}

	

	
	
}
