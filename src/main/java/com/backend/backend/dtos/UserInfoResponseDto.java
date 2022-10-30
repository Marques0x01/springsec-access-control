package com.backend.backend.dtos;

import com.backend.backend.models.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserInfoResponseDto {
	private String id;
	private String email;
	private List<Role> roles;
}
