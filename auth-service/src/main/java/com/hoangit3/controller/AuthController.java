package com.hoangit3.controller;

import com.hoangit3.dto.UsernameAuthoritiesDto;
import com.hoangit3.model.ERole;
import com.hoangit3.model.Role;
import com.hoangit3.model.User;
import com.hoangit3.payload.request.LoginRequest;
import com.hoangit3.payload.request.SignUpRequest;
import com.hoangit3.payload.response.JwtResponse;
import com.hoangit3.payload.response.MessageResponse;
import com.hoangit3.repositories.RoleRepository;
import com.hoangit3.repositories.UserRepository;
import com.hoangit3.security.JwtUtils;
import com.hoangit3.services.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping(path = "/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;


    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping(path = "/authinfo")
    public ResponseEntity<UsernameAuthoritiesDto> authorizationInformation() {
        UserDetails userDetails = getPrincipal();
        UsernameAuthoritiesDto usernameAuthoritiesDto = new UsernameAuthoritiesDto();
        usernameAuthoritiesDto.setUsername(userDetails.getUsername());
        Set<String> authorities = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        usernameAuthoritiesDto.setAuthorities(authorities);
        return ResponseEntity.ok(usernameAuthoritiesDto);
    }

    private UserDetails getPrincipal() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            return (UserDetailsImpl) principal;
        }
        return null;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Optional<Role> userRole = roleRepository.findByName(ERole.ROLE_USER);
            if (userRole.isEmpty()) {
                Role role = new Role(ERole.ROLE_USER);
                roles.add(role);
            } else
                roles.add(userRole.get());
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Optional<Role> adminRole = roleRepository.findByName(ERole.ROLE_ADMIN);
                        if (adminRole.isEmpty()) {
                            Role r = new Role(ERole.ROLE_ADMIN);
                            roles.add(r);
                        } else
                            roles.add(adminRole.get());

                        break;
                    case "moderator":
                        Optional<Role> moderatorRole = roleRepository.findByName(ERole.ROLE_MODERATOR);
                        if (moderatorRole.isEmpty()) {
                            Role r = new Role(ERole.ROLE_MODERATOR);
                            roles.add(r);
                        } else
                            roles.add(moderatorRole.get());

                        break;
                    default:
                        Optional<Role> userRole = roleRepository.findByName(ERole.ROLE_USER);
                        if (userRole.isEmpty()) {
                            Role r = new Role(ERole.ROLE_USER);
                            roles.add(r);
                        } else
                            roles.add(userRole.get());
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @GetMapping("/current-user")
    public UserDetails getCurrentUser() {
        return (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication()
                .getPrincipal();
    }
}
