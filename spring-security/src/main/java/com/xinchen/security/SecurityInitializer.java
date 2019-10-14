package com.xinchen.security;


import com.xinchen.security.config.WebMvcConfig;
import com.xinchen.security.config.WebSecurityConfig;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

import javax.servlet.ServletContext;

/**
 */
public class SecurityInitializer  extends AbstractSecurityWebApplicationInitializer {
    protected SecurityInitializer() {
        super(WebSecurityConfig.class,WebMvcConfig.class);
    }
    //    @Override
//    protected Class<?>[] getRootConfigClasses() {
//        return new Class[]{WebSecurityConfig.class};
//    }
//
//    @Override
//    protected Class<?>[] getServletConfigClasses() {
//        AbstractSecurityWebApplicationInitializer
//        return new Class[]{WebMvcConfig.class};
//    }
//
//    @Override
//    protected String[] getServletMappings() {
//        return new String[]{"/*"};
//    }
//
//    @Override
//    protected void customizeRegistration(ServletRegistration.Dynamic registration) {
//        registration.setLoadOnStartup(1);
//    }


    @Override
    protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
        super.afterSpringSecurityFilterChain(servletContext);
    }
}
