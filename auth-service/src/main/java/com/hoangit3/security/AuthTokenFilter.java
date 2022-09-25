package com.hoangit3.security;

import com.hoangit3.services.UserDetailsImpl;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    private final JwtUtils jwtUtils;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Autowired
    public AuthTokenFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    // activate per request
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = jwtUtils.parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // parse jwt and set authentication object into security context holder
                setAuthenticationContext(jwt, request);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        filterChain.doFilter(request, response);
    }

    private void setAuthenticationContext(String token, HttpServletRequest request) {
        UserDetails userDetails = getUserDetails(token);

        UsernamePasswordAuthenticationToken
                authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private UserDetails getUserDetails(String token) {
        UserDetailsImpl userDetails = new UserDetailsImpl();
        Claims claims = jwtUtils.parseClaims(token);
        String subjects = (String) claims.get(Claims.SUBJECT);
        String[] part = subjects.split(",");
        String roles = (String) claims.get("authorities");

        roles = roles.replace("[", "").replace("]", "");
        String[] roleNames = roles.split(",");
        Set<SimpleGrantedAuthority> authorities = Arrays.stream(roleNames).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        userDetails.setId(Long.parseLong(part[0]));
        userDetails.setUsername(part[1]);
        userDetails.setAuthorities(authorities);
        return userDetails;
    }
}
