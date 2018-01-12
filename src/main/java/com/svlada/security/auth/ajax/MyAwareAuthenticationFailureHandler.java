package com.svlada.security.auth.ajax;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.svlada.common.ErrorCode;
import com.svlada.common.ErrorResponse;
import com.svlada.security.exceptions.AuthMethodNotSupportedException;
import com.svlada.security.exceptions.JwtExpiredTokenException;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 3, 2016
 */
@Component
public class MyAwareAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final Gson gson;
    
    @Autowired
    public MyAwareAuthenticationFailureHandler(Gson gson) {
        this.gson = gson;
    }	
    
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);

		if (e instanceof BadCredentialsException) {
			response.getWriter().write(gson.toJson(ErrorResponse.of("Invalid username or password", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)));
		} else if (e instanceof JwtExpiredTokenException) {
			response.getWriter().write(gson.toJson(ErrorResponse.of("Token has expired", ErrorCode.JWT_TOKEN_EXPIRED, HttpStatus.UNAUTHORIZED)));
		} else if (e instanceof AuthMethodNotSupportedException) {
			response.getWriter().write(gson.toJson(ErrorResponse.of(e.getMessage(), ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)));
		}

		response.getWriter().write(gson.toJson(ErrorResponse.of("Authentication failed", ErrorCode.AUTHENTICATION, HttpStatus.UNAUTHORIZED)));
	}
}
