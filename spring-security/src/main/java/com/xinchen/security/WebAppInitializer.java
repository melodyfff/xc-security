package com.xinchen.security;

import com.xinchen.security.config.RootConfig;
import com.xinchen.security.config.WebMvcConfig;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.FrameworkServlet;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

import javax.servlet.ServletRegistration;

/**
 *
 * dispatchServlet和Root WebApplicationContext初始化
 *
 * @author xinchen
 * @version 1.0
 * @date 15/10/2019 13:55
 */
public class WebAppInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {
    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class[]{RootConfig.class};
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class[]{WebMvcConfig.class};
    }

    @Override
    protected String[] getServletMappings() {
        return new String[]{"/*"};
    }

    @Override
    protected void customizeRegistration(ServletRegistration.Dynamic registration) {
        // 设置在debug/trace日志级别的时候打印请求的详细信息
        registration.setInitParameter("enableLoggingRequestDetails", "true");
    }

    @Override
    protected String getServletName() {
        // 设置Servlet名字
        return "app";
    }

    @Override
    protected FrameworkServlet createDispatcherServlet(WebApplicationContext servletAppContext) {
        final DispatcherServlet dispatcherServlet = new DispatcherServlet(servletAppContext);

        // 处理dispatcherServlet,开启抛出异常,自己处理404等
        dispatcherServlet.setThrowExceptionIfNoHandlerFound(true);
        return dispatcherServlet;
    }
}
