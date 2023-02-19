package com.cos.sjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.sjwt.model.User;

public interface UserRepository extends JpaRepository<User,Long>{
	
	public User findByUsername(String username);

}
