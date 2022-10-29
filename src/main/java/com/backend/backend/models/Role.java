package com.backend.backend.models;


import com.backend.backend.enums.RoleEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;

@Data
@Document
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Role implements GrantedAuthority {

    @Id
    private String id;
    private RoleEnum name;

    @Override
    public String getAuthority() {
        return this.name.toString();
    }
}
