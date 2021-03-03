package com.felipeandrade0918.springjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.felipeandrade0918.springjwt.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

	@Query("SELECT u FROM User u WHERE u.username = :username")
	User findOneByUsername(String username);
}
