package com.rallynation.rallynation_mlb.auth;

public class PasswordTooLongException extends RuntimeException {

	public PasswordTooLongException() {
		super("Password must not exceed 72 UTF-8 bytes");
	}
}
