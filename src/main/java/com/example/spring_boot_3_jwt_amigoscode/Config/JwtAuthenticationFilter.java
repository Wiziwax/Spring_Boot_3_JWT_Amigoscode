package com.example.spring_boot_3_jwt_amigoscode.Config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    //This class is used to verify the JWT for every request made
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        //This first 'If' statement checks if there's any header or if it starts with 'Bearer',
        // if both conditions are null, then there's no need to continue with the JWT check
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

        //The functions below, is used to extract the User Email from jwt token
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        //After checking the JWT Token, the next thing is to call the UserDetail Service to check if the User exists or not

    }
}
