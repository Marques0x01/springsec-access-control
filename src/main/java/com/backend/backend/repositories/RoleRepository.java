package com.backend.backend.repositories;

import com.backend.backend.enums.ERole;
import com.backend.backend.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {

    Optional<Role> findByName(ERole name);

}
