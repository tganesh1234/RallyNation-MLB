package com.rallynation.rallynation_mlb.auth;

import com.rallynation.rallynation_mlb.auth.AuthDtos.ApiError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class AuthExceptionHandler {

	@ExceptionHandler(DuplicateEmailException.class)
	public ResponseEntity<ApiError> handleDuplicateEmail(DuplicateEmailException exception) {
		return ResponseEntity.status(HttpStatus.CONFLICT).body(new ApiError(exception.getMessage()));
	}

	@ExceptionHandler(PasswordTooLongException.class)
	public ResponseEntity<ApiError> handlePasswordTooLong(PasswordTooLongException exception) {
		return ResponseEntity.badRequest().body(new ApiError(exception.getMessage()));
	}

	@ExceptionHandler(AuthenticationException.class)
	public ResponseEntity<ApiError> handleAuthenticationFailure() {
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(new ApiError("Invalid email or password"));
	}
}
