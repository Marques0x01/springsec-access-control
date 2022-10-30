package com.backend.backend.controllers;

import com.backend.backend.configs.jwt.JwtUtils;
import com.backend.backend.enums.ERole;
import com.backend.backend.exception.TokenRefreshException;
import com.backend.backend.models.RefreshToken;
import com.backend.backend.models.Role;
import com.backend.backend.models.User;
import com.backend.backend.dtos.LoginRequestDto;
import com.backend.backend.dtos.SignupRequestDto;
import com.backend.backend.dtos.MessageResponseDto;
import com.backend.backend.dtos.UserInfoResponseDto;
import com.backend.backend.repositories.RoleRepository;
import com.backend.backend.repositories.UserRepository;
import com.backend.backend.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
  @Autowired
  private AuthenticationManager authenticationManager;

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private RoleRepository roleRepository;

  @Autowired
  private PasswordEncoder encoder;

  @Autowired
  private JwtUtils jwtUtils;

  @Autowired
  private AuthService authService;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequestDto loginRequestDto) {

    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserDetails userDetails =
            (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

    User user = userRepository.findByEmail(userDetails.getUsername()).orElseThrow(() ->
            new UsernameNotFoundException("User Not Found with username: " + userDetails.getPassword()));

    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails.getUsername());

    RefreshToken refreshToken = authService.createRefreshToken(user);
    ResponseCookie jwtRefreshCookie = jwtUtils.generateRefreshJwtCookie(refreshToken.getToken());

    return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
            .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
            .body(new UserInfoResponseDto(user.getId(),
                    user.getEmail(),
                    user.getRoles()));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequestDto signUpRequestDto) throws Exception {
    if (userRepository.existsByEmail(signUpRequestDto.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponseDto("Error: Username is already taken!"));
    }

    List<ERole> requestRoles = signUpRequestDto.getRole();
    List<Role> roles = new ArrayList<>();

    if(requestRoles == null || requestRoles.isEmpty()){
      roles.addAll(Arrays.asList(roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Role not found"))));
    } else {
      requestRoles.forEach(role -> {
        switch (role) {
          case ROLE_ADMIN:
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(adminRole);

            break;
          case ROLE_MOD:
            Role modRole = roleRepository.findByName(ERole.ROLE_MOD)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(modRole);

            break;
          default:
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }
      });
    }

    User user = User.builder()
            .name(signUpRequestDto.getName())
            .email(signUpRequestDto.getEmail())
            .password(new BCryptPasswordEncoder().encode(signUpRequestDto.getPassword()))
            .roles(roles)
            .build();


    userRepository.save(user);

    return ResponseEntity.ok()
            .body(new UserInfoResponseDto(user.getId(),
                    user.getEmail(),
                    user.getRoles()));
  }

  @PostMapping("/signout")
  public ResponseEntity<?> logoutUser() {
    Object principle = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    if (principle.toString() != "anonymousUser") {
      String userId = ((User) principle).getId();
      authService.deleteByUserId(userId);
    }

    ResponseCookie jwtCookie = jwtUtils.getCleanJwtCookie();
    ResponseCookie jwtRefreshCookie = jwtUtils.getCleanJwtRefreshCookie();

    return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
            .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
            .body(new MessageResponseDto("You've been signed out!"));
  }

  @PostMapping("/refreshtoken")
  public ResponseEntity<?> refreshtoken(HttpServletRequest request) {
    String refreshToken = jwtUtils.getJwtRefreshFromCookies(request);

    if ((refreshToken == null) && (refreshToken.length() <= 0)) {
      return ResponseEntity.badRequest().body(new MessageResponseDto("Refresh Token is empty!"));
    }

    return authService.findByToken(refreshToken)
            .map(authService::verifyExpiration)
            .map(RefreshToken::getUser)
            .map(user -> {
              ResponseCookie newJwtCookie = jwtUtils.generateJwtCookie(user.getEmail());

              RefreshToken newRefreshToken = authService.createRefreshToken(user);
              ResponseCookie newJwtRefreshCookie = jwtUtils.generateRefreshJwtCookie(newRefreshToken.getToken());

              return ResponseEntity.ok()
                      .header(HttpHeaders.SET_COOKIE, newJwtCookie.toString())
                      .header(HttpHeaders.SET_COOKIE, newJwtRefreshCookie.toString())
                      .body(new MessageResponseDto("Token is refreshed successfully!"));
            })
            .orElseThrow(() -> new TokenRefreshException(refreshToken,
                    "Refresh token is not in database!"));

  }

}
