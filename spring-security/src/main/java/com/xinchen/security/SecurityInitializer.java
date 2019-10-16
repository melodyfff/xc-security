package com.xinchen.security;


import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.web.SpringServletContainerInitializer;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.Filter;
import javax.servlet.ServletContext;
import java.util.Set;


/**
 *
 * security 环境加载
 *
 * 在其他的 {@link Filter} 注册之前,提前注册{@link DelegatingFilterProxy} 默认名字为: springSecurityFilterChain
 *
 * 对于多个实现了{@link WebApplicationInitializer} 接口的环境初始化,
 *
 * {@link SpringServletContainerInitializer#onStartup(Set, ServletContext)}中会遍历加载配置环境
 *
 * spring security的filter排序由{@link org.springframework.security.config.annotation.web.builders.FilterComparator}控制
 *
 * Security filter chain: [
 *   WebAsyncManagerIntegrationFilter
 *   SecurityContextPersistenceFilter
 *   HeaderWriterFilter
 *   CsrfFilter
 *   LogoutFilter
 *   UsernamePasswordAuthenticationFilter
 *   DefaultLoginPageGeneratingFilter
 *   DefaultLogoutPageGeneratingFilter
 *   BasicAuthenticationFilter
 *   RequestCacheAwareFilter
 *   SecurityContextHolderAwareRequestFilter
 *   AnonymousAuthenticationFilter
 *   SessionManagementFilter
 *   ExceptionTranslationFilter
 *   FilterSecurityInterceptor   (class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter)
 * ]
 *
 */
public class SecurityInitializer  extends AbstractSecurityWebApplicationInitializer {
}
