package com.rallynation.rallynation_mlb.auth;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;

import com.rallynation.rallynation_mlb.auth.AuthDtos.LoginRequest;
import com.rallynation.rallynation_mlb.auth.AuthDtos.RegisterRequest;
import com.rallynation.rallynation_mlb.auth.AuthDtos.TokenResponse;
import com.rallynation.rallynation_mlb.auth.AuthDtos.UserResponse;
import com.rallynation.rallynation_mlb.user.User;
import com.rallynation.rallynation_mlb.user.UserRepository;
import com.rallynation.rallynation_mlb.user.UserRole;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

	private final UserRepository users;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final JwtEncoder jwtEncoder;
	private final JwtProperties jwtProperties;

	public AuthService(
			UserRepository users,
			PasswordEncoder passwordEncoder,
			AuthenticationManager authenticationManager,
			JwtEncoder jwtEncoder,
			JwtProperties jwtProperties) {
		this.users = users;
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.jwtEncoder = jwtEncoder;
		this.jwtProperties = jwtProperties;
	}

	@Transactional
	public UserResponse register(RegisterRequest request) {
		validatePasswordLength(request.password());
		String email = normalizeEmail(request.email());
		if (users.existsByEmail(email)) {
			throw new DuplicateEmailException();
		}

		User user = new User(email, passwordEncoder.encode(request.password()), UserRole.ROLE_USER);
		try {
			users.saveAndFlush(user);
		}
		catch (DataIntegrityViolationException exception) {
			throw new DuplicateEmailException();
		}
		return new UserResponse(user.getEmail());
	}

	public TokenResponse login(LoginRequest request) {
		validatePasswordLength(request.password());
		String email = normalizeEmail(request.email());
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(email, request.password()));

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(jwtProperties.accessTokenTtl());
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer(jwtProperties.issuer())
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.subject(authentication.getName())
				.claim("roles", authentication.getAuthorities().stream()
						.map(GrantedAuthority::getAuthority)
						.toList())
				.build();

		JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
		String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
		return new TokenResponse(token, "Bearer", jwtProperties.accessTokenTtl().toSeconds());
	}

	private String normalizeEmail(String email) {
		return email.trim().toLowerCase(Locale.ROOT);
	}

	private void validatePasswordLength(String password) {
		if (password.getBytes(StandardCharsets.UTF_8).length > 72) {
			throw new PasswordTooLongException();
		}
	}
}
