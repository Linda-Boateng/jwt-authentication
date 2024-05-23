package com.tutorial.jwtauthentication.auth;


import com.tutorial.jwtauthentication.config.JwtService;
import com.tutorial.jwtauthentication.user.Role;
import com.tutorial.jwtauthentication.user.User;
import com.tutorial.jwtauthentication.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authentication(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()

                )
        );
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .userId(user.getId())
                .build();
    }

    public UpdateResponse updateUser(Integer userId, UpdateRequest request) {
    User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User Not Found"));
    user.setEmail(request.getEmail());
    user.setLastname(request.getLastname());
    user.setFirstname(request.getFirstname());
    userRepository.save(user);
        return UpdateResponse.builder().message("User updated Successfully").build();
    }
}
