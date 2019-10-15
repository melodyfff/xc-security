package com.xinchen.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author xinchen
 * @version 1.0
 * @date 15/10/2019 13:54
 */
@Configuration
@Import(WebSecurityConfig.class)
public class RootConfig {
}
