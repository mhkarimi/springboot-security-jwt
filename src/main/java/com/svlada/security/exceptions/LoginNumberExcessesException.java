package com.svlada.security.exceptions;

import org.springframework.security.core.AuthenticationException;

public class LoginNumberExcessesException extends AuthenticationException {
    public LoginNumberExcessesException(String message) {
        super(message);
    }
}
