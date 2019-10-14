package security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @author xinchen
 * @version 1.0
 * @date 30/09/2019 14:26
 */
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.builder().username("hello")
                .password("hello")
                .roles("USER")
                .passwordEncoder((password)-> passwordEncoder().encode(password))
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(4);
    }
}
