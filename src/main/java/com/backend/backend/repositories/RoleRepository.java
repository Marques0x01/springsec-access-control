package com.backend.backend.repositories;

import com.backend.backend.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface RoleRepository extends MongoRepository<Role, String> {

}
