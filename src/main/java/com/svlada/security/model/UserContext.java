package com.svlada.security.model;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;

/**
 * 
 * @author vladimir.stankovic
 *
 * Aug 4, 2016
 */
public class UserContext {
    private final String username;
    private final List<GrantedAuthority> authorities;
    private Integer numberOfLogins = 0;

    private UserContext(String username, List<GrantedAuthority> authorities) {
        this.username = username;
        this.authorities = authorities;
    }

    public UserContext(String username, List<GrantedAuthority> authorities, Integer numberOfLogins) {
        this.username = username;
        this.authorities = authorities;
        this.numberOfLogins = numberOfLogins;
    }

    public static UserContext create(String username, List<GrantedAuthority> authorities) {
        if (StringUtils.isBlank(username)) throw new IllegalArgumentException("Username is blank: " + username);
        return new UserContext(username, authorities);
    }

    public String getUsername() {
        return username;
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Integer getNumberOfLogins() {
        return numberOfLogins;
    }

    public void setNumberOfLogins(Integer numberOfLogins) {
        this.numberOfLogins = numberOfLogins;
    }
}
