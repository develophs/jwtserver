package com.cos.sjwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.sjwt.model.User;
import com.cos.sjwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8080/login 요청이오면 동작
// 하지만 formLogin을 안하면 동작을 안한다.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUsername(username);
		return new PrincipalDetails(userEntity);
	}

	
}
