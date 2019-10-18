package com.xinchen.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.io.IOException;
import java.util.Properties;

/**
 * @author xinchen
 * @version 1.0
 * @date 14/10/2019 15:20
 */
@EnableWebSecurity(debug = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .httpBasic()
                .and()
                .formLogin().permitAll().defaultSuccessUrl("/login/success").failureForwardUrl("/login/fail")
                .and()
                .logout().permitAll().logoutSuccessUrl("/logout/success");
    }

    @Override
    @Bean
    public UserDetailsService userDetailsService(){
        Properties properties = new Properties();
        try {
            properties.load(getClass().getClassLoader().getResourceAsStream("user.properties"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        //  UserDetails user = User.builder().username("admin")
        //          .password("admin")
        //          .roles("USER")
        //          .passwordEncoder((password)-> passwordEncoder().encode(password))
        //          .build();
        //  new InMemoryUserDetailsManager(user);

        // 加载文件中的用户
        return new InMemoryUserDetailsManager(properties);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 建立全局的AuthenticationManagerBuilder
        // <code>@Autowired public void initialize(AuthenticationManagerBuilder builder, DataSource dataSource) {}</code>
        // 这里的AuthenticationManagerBuilder只是全局变量的子级
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }

    @Bean
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(4);
    }
}
