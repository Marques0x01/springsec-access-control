package com.backend.backend;

import com.backend.backend.enums.ERole;
import com.backend.backend.models.Role;
import com.backend.backend.models.User;
import com.backend.backend.repositories.RoleRepository;
import com.backend.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Arrays;

@SpringBootApplication
public class BackendApplication implements CommandLineRunner {

	@Autowired
	private RoleRepository roleRepository;

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		Role role1 = Role.builder()
				.name(ERole.ROLE_ADMIN)
				.build();

		Role role2 = Role.builder()
				.name(ERole.ROLE_USER)
				.build();

		Role role3 = Role.builder()
				.name(ERole.ROLE_TESTE)
				.build();
//
//		roleRepository.saveAll(Arrays.asList(role1, role2, role3));

	}
}
