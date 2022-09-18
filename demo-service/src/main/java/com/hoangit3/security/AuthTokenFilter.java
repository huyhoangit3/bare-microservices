package com.hoangit3.security;

import com.hoangit3.dto.UsernameAuthoritiesDto;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {

    private final RestTemplate restTemplate;
    private final AuthInfo authInfo;
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String jwtToken = parseJwt(request);
        if (jwtToken != null) {
            //call auth-service
            UsernameAuthoritiesDto authenticationInformation =
                    getAuthenticationInformation(authInfo.getAuthenticatedInfoUrl(), jwtToken);
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authenticationInformation.getAuthorities().stream().map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
            PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken =
                    new PreAuthenticatedAuthenticationToken(authenticationInformation.getUsername(), null, simpleGrantedAuthorities);
            SecurityContextHolder.getContext().setAuthentication(preAuthenticatedAuthenticationToken);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }

    private UsernameAuthoritiesDto getAuthenticationInformation(String authenticatedInfoUrl, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(headers);
        ResponseEntity<UsernameAuthoritiesDto> response = restTemplate.postForEntity(authenticatedInfoUrl, entity, UsernameAuthoritiesDto.class);
        return response.getBody();
    }
}
