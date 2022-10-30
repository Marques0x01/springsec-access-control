package com.backend.backend.dtos;

import com.backend.backend.enums.ERole;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.List;

@Data
public class SignupRequestDto {
    @NotBlank
    @Size(min = 3, max = 20)
    private String name;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;
    
    private List<ERole> role;
    
    @NotBlank
    @Size(min = 6, max = 40)
    private String password;

}
