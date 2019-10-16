package com.xinchen.security.example;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * 身份认证实例
 *
 * {@link AuthenticationManager} 认证管理器,处理{@link Authentication}请求,返回一个完全填充的{@link Authentication}实例
 *
 * {@link GrantedAuthority} 授予的权限
 *
 * 参考: https://docs.spring.io/spring-security/site/docs/5.2.1.BUILD-SNAPSHOT/reference/htmlsingle/#tech-intro-authentication
 *
 * @author xinchen
 * @version 1.0
 * @date 16/10/2019 11:07
 */
public class AuthenticationExample {
    private static AuthenticationManager am = new SampleAuthenticationManager();

    public static void main(String[] args) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        while (true){

            System.out.println("Please enter your username:");
            String name = in.readLine();
            System.out.println("Please enter your password:");
            String password = in.readLine();

            try {
                Authentication request = new UsernamePasswordAuthenticationToken(name, password);
                Authentication result = am.authenticate(request);
                SecurityContextHolder.getContext().setAuthentication(result);
                break;
            } catch(AuthenticationException e) {
                System.out.println("Authentication failed: " + e.getMessage());
            }
        }

        System.out.println("Successfully authenticated. Security context contains: " +
                SecurityContextHolder.getContext().getAuthentication());
    }
}

class SampleAuthenticationManager implements AuthenticationManager{

    static final List<GrantedAuthority> AUTHORITIES = new ArrayList<>();

    static {
        // 初始化角色
        AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // authentication.getCredentials() 通常是密码
        if (authentication.getName().equals(authentication.getCredentials())){
            // Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities
            return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(), AUTHORITIES);
        }
        throw new BadCredentialsException("Bad Credentials");
    }
}
