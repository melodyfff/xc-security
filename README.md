# xc-security

## Architecture and Implementation(架构与实现)
应用程序安全性可以归结为或多或少的两个独立问题：身份验证（您是谁）和授权（您可以做什么？）

---

### Summary(摘要)
`Spring Security`的主要组成部分:
- `SecurityContextHolder`，提供对的访问`SecurityContext`。
- `SecurityContext`，以保存`Authentication`（可能还有特定于请求的）安全信息。
- `Authentication`，以特定于`Spring Security`的方式表示主体。
- `GrantedAuthority`，以反映授予主体的应用程序范围的权限。
- `UserDetails`，以提供必要的信息以从应用程序的DAO或其他安全数据源构建`Authentication`对象。
- `UserDetailsService`，以`UserDetails`在传入String基于-的用户名（或证书ID等）时创建一个。

---

### Authentication(身份验证)

#### What is authentication in Spring Security?
`Spring Security`中的身份验证:
- 获取用户名和密码，并将其组合到的一个实例`UsernamePasswordAuthenticationToken`（`Authentication`接口的实例）。
- 令牌会传递到的实例`AuthenticationManager`进行验证。
- 成功认证后 ，`AuthenticationManager`返回一个完全填充的`Authentication`实例。
- 通过调用`SecurityContextHolder.getContext().setAuthentication(…​)`并传入返回的身份验证对象来建立安全上下文。

**官网实例:**
```java
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
```

---

### Authentication in a Web Application
考虑典型的`Web`应用程序的身份验证过程：
- 1.您访问主页，然后单击链接。
- 2.请求发送到服务器，服务器确定您已请求受保护的资源。
- 3.由于您目前尚未通过身份验证，因此服务器会发回响应，指示您必须进行身份验证。响应将是HTTP响应代码，或重定向到特定网页。
- 4.根据身份验证机制，您的浏览器将重定向到特定网页，以便您可以填写表格，或者浏览器将以某种方式检索您的身份（通过BASIC身份验证对话框，cookie，X.509证书等）。 ）。
- 5.浏览器将响应发送回服务器。这将是包含您填写的表单内容的HTTP POST或包含身份验证详细信息的HTTP标头。
- 6.接下来，服务器将决定所提供的凭据是否有效。如果有效，则将进行下一步。如果它们无效，通常会要求您的浏览器再试一次（因此您返回到上面的第二步）。
- 7.您尝试引起身份验证过程的原始请求将被重试。希望您已获得足够授权的身份验证，以访问受保护的资源。如果您具有足够的访问权限，则请求将成功。否则，您将收到一个HTTP错误代码403，表示“禁止”。

`Spring Security`具有负责上述大多数步骤的不同类。
主要参与者（按照使用顺序）是`ExceptionTranslationFilter`，`AuthenticationEntryPoint`和和`“Authentication Mechanism(身份验证机制)”`，它们负责调用`AuthenticationManager`

#### ExceptionTranslationFilter
`ExceptionTranslationFilter`是一个Spring Security过滤器，它负责检测抛出的任何Spring Security异常(`AccessDeniedException`和`AuthenticationException`).
此类异常通常由`AbstractSecurityInterceptor`授权服务的主要提供者抛出

#### AuthenticationEntryPoint
`AuthenticationEntryPoint(认证入口点)`主要负责上述步骤中的第`3`步.
主要是在`ExceptionTranslationFilter`中通过捕获到`AuthenticationException`异常后,
调用`handleSpringSecurityException(...)`在此方法中的`sendStartAuthentication(...)`开启认证方案

#### Authentication Mechanism
`Authentication Mechanism(身份验证机制)`,
一旦您的浏览器提交了身份验证凭据(authentication credentials)（作为HTTP表单帖子或HTTP标头
,服务器上就需要有一些东西来“收集”这些身份验证详细信息。到目前为止，我们位于上述列表的第`6`步.
在`Spring Security`中，我们有一个特殊的名称，用于从用户代理（通常是Web浏览器）收集身份验证详细信息的功能，将其称为`Authentication Mechanism(身份验证机制)`。
从用户代理收集到身份验证详细信息后，`Authentication`便会构建一个`“请求”`对象，然后将其呈现给`AuthenticationManager`

`Authentication Mechanism(身份验证机制)`收到完整的`Authentication(从AuthenticationManager中返回)`对象后，
它将认为请求有效，将`Authentication`放入`SecurityContextHolder`，
并导致重试原始请求（上述步骤`7`）。
另一方面，如果`AuthenticationManager`拒绝了请求，
则认证机制将要求用户代理重试（上面的第`2`步）。

通常`AuthenticationManager`中的返回:
- 如果它可以验证输入是否代表有效的主体，则返回`Authentication`（通常为`authenticated=true`）
- 如果它认为输入代表无效的主体，则抛出一个`AuthenticationException`
- 如果无法决定，则返回 `null`

#### Storing the SecurityContext between requests
在请求之间如何存储`SecurityContext`?根据应用程序的类型，可能需要制定一种策略来存储用户操作之间的安全上下文。在典型的Web应用程序中，用户登录一次，然后通过其会话ID(`session id`)进行标识。
有效期取决于服务器`session`的过期时间.

在`Spring Security`中，存储`SecurityContext`请求之间的责任落在`SecurityContextPersistenceFilter`，
默认情况下，将上下文存储为`HttpSession`HTTP请求之间的属性(将设置`request.setAttribute(FILTER_APPLIED, Boolean.TRUE);`保证值执行一次)。
它将上下文`SecurityContextHolder`还原到每个请求，并且至关重要的是，当请求完成时清除`SecurityContextHolder`


`SecurityContextPersistenceFilter`中真正存储由`SecurityContextRepository`完成,通过调用`loadContext(...)加载`其中:
- `NullSecurityContextRepository`实际上是每次都生成新的`SecurityContextHolder.createEmptyContext()`
- `HttpSessionSecurityContextRepository`实际上是存储在`HttpSession`中,默认属性值为`SPRING_SECURITY_CONTEXT`,可以通过修改`springSecurityContextKey`自定义该值

许多其他类型的应用程序（例如，无状态RESTful Web服务）不使用HTTP会话，并且将在每个请求上重新进行身份验证。
但是，仍然必须确保链中包含`SecurityContextPersistenceFilter`，以确保`SecurityContextHolder`在每次请求后清除。

---

### Access-Control (Authorization) in Spring Security
在`Spring Security`中负责做出访问控制决策的主要接口是`AccessDecisionManager`。它具有一种`decide`方法，该方法采用`Authentication`代表请求访问的主体的对象，`“secure object(安全对象)”`（请参见下文）以及适用于该对象的安全元数据属性列表（例如授予访问权限所需的角色列表） ）。

#### Security and AOP Advice
您可以选择使用`AspectJ`或`Spring AOP`执行方法授权，也可以选择使用过滤器执行Web请求授权,`Spring Security`中主要是`AbstractSecurityInterceptor`的继承类`FilterSecurityInterceptor`贯穿整个周期

#### Secure Objects and the AbstractSecurityInterceptor
那么，什么是 `“secure object(安全对象)”`？`Spring Security`使用该术语来指代任何可以对其应用安全性（例如授权决策）的对象。最常见的示例是方法调用和Web请求。

每个受支持的安全对象类型都有其自己的拦截器类(`AbstractSecurityInterceptor`的子类),
重要的是,当`AbstractSecurityInterceptor`被调用时,如果`principal(主体)`已通过身份验证，
`SecurityContextHolder`则将包含有效`Authentication`的内容。

`AbstractSecurityInterceptor` 提供用于处理安全对象请求的一致工作流，通常是：

- 1.查找与当前请求关联的`“configuration attributes(配置属性)”`
- 2.将安全对象，当前`Authentication`属性和配置属性提交`AccessDecisionManager`给授权决策
- 3.（可选）更改`Authentication`调用的依据
- 4.允许进行安全对象调用（假设已授予访问权限）
- 5.调用返回后如果配置了`AfterInvocationManager`,则调用。一旦调用引发了异常，`AfterInvocationManager`则不会调用。

##### What are Configuration Attributes(配置属性)?

![](doc/img/authentication.png)