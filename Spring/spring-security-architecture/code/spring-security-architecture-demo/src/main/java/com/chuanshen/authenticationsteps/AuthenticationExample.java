package com.chuanshen.authenticationsteps;

import jdk.nashorn.internal.ir.CallNode;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * @Auther: Chuan Shen
 * @Date: 2020/4/15 10:52
 * @Description:
 **/
public class AuthenticationExample {
    private static AuthenticationManager am = new SampleAuthenticationManger();

    public static void main(String args[]) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        while (true) {
            System.out.println("Please enter your username:");
            String username = in.readLine();
            System.out.println("Please enter your password:");
            String password = in.readLine();
            try {
                Authentication authRequest = new UsernamePasswordAuthenticationToken(username, password);
                Authentication authResult = am.authenticate(authRequest);
                SecurityContextHolder.getContext().setAuthentication(authResult);
                break;
            }  catch (AuthenticationException e) {
                System.out.println("Authentication failed:" + e.getMessage());
            }
        }
        System.out.println("Successfully authenticated. Security context contains:" +
                SecurityContextHolder.getContext().getAuthentication());
    }

}

class SampleAuthenticationManger implements AuthenticationManager {
    static final List<GrantedAuthority> AUTHORITIES = new ArrayList<GrantedAuthority>();
    static {
        AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
        AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication.getName().equals(authentication.getCredentials())) {
            return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(), AUTHORITIES);
        }
        throw new BadCredentialsException("Bad Credentials");
    }
}
