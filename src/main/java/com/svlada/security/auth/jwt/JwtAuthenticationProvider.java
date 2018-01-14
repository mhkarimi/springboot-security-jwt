package com.svlada.security.auth.jwt;

import java.util.List;
import java.util.stream.Collectors;

import com.svlada.security.exceptions.LoginNumberExcessesException;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.svlada.security.auth.JwtAuthenticationToken;
import com.svlada.security.config.JwtSettings;
import com.svlada.security.model.UserContext;
import com.svlada.security.model.token.JwtToken;
import com.svlada.security.model.token.RawAccessJwtToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import javax.annotation.PostConstruct;
import javax.jnlp.IntegrationService;

/**
 * An {@link AuthenticationProvider} implementation that will use provided
 * instance of {@link JwtToken} to perform authentication.
 *
 * @author vladimir.stankovic
 * <p>
 * Aug 5, 2016
 */
@Component
@SuppressWarnings("unchecked")
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtSettings jwtSettings;
    private ValueOperations valueOperations;
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    public JwtAuthenticationProvider(JwtSettings jwtSettings) {
        this.jwtSettings = jwtSettings;
    }


    @PostConstruct
    private void init() {
        valueOperations = redisTemplate.opsForValue();
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        //System.out.println("\n\n\n\n\n" + valueOperations.get("mmmm") + "\n\n\n\n\n");
        //System.out.println("\n\n\n\n\n" + valueOperations.get("sdsd") + "\n\n\n\n\n");
        //valueOperations.set("mmmm","Kachal");
        //TODO
        // Redis consideration shall be here
        RawAccessJwtToken rawAccessToken = (RawAccessJwtToken) authentication.getCredentials();

        Jws<Claims> jwsClaims = rawAccessToken.parseClaims(jwtSettings.getTokenSigningKey());
        String subject = jwsClaims.getBody().getSubject();
        List<String> scopes = jwsClaims.getBody().get("scopes", List.class);
        List<GrantedAuthority> authorities = scopes.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UserContext context = UserContext.create(subject, authorities);
        Integer result = valueOperations.increment(subject, +1l).intValue();
        System.out.println("\n\n\n\n\n" + result + "\n\n\n\n\n");
        if(result > 4) {
            //redisTemplate.delete(subject);
            throw new LoginNumberExcessesException("you exceeded login numbers");
        }
        context.setNumberOfLogins(result);
        return new JwtAuthenticationToken(context, context.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
