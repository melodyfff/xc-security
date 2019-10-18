package com.xinchen.security.example;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 密码加密
 * @author xinchen
 * @version 1.0
 * @date 18/10/2019 10:36
 */
public class BCryptPasswordEncoderExample {
    public static void main(String[] args) {
        final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
        System.out.println(encoder.encode("admin"));
    }
}
