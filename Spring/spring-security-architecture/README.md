
这是一篇 Spring Security 体系结构的系列文章

源于 [徐靖峰 - Spring Security](https://www.cnkirito.moe/categories/Spring-Security/) 

---

<!-- TOC -->

- [1 Spring Security Architecture Overview 核心组件](#1-spring-security-architecture-overview-%e6%a0%b8%e5%bf%83%e7%bb%84%e4%bb%b6)
  - [1.1 SecurityContextHolder](#11-securitycontextholder)
    - [获取当前用户的信息](#%e8%8e%b7%e5%8f%96%e5%bd%93%e5%89%8d%e7%94%a8%e6%88%b7%e7%9a%84%e4%bf%a1%e6%81%af)
  - [1.2 Authentication](#12-authentication)
    - [Spring Security 是如何完成身份认证的](#spring-security-%e6%98%af%e5%a6%82%e4%bd%95%e5%ae%8c%e6%88%90%e8%ba%ab%e4%bb%bd%e8%ae%a4%e8%af%81%e7%9a%84)
  - [1.3 AuthenticationManager](#13-authenticationmanager)
  - [1.4 DaoAuthenticationProvider](#14-daoauthenticationprovider)
  - [1.5 UserDetails 与 UserDetailsService](#15-userdetails-%e4%b8%8e-userdetailsservice)
  - [1.6 架构概览图](#16-%e6%9e%b6%e6%9e%84%e6%a6%82%e8%a7%88%e5%9b%be)
- [2 Spring Security Guides](#2-spring-security-guides)
  - [2.1 引入依赖](#21-%e5%bc%95%e5%85%a5%e4%be%9d%e8%b5%96)
  - [2.2 创建一个不受安全限制的 web 应用](#22-%e5%88%9b%e5%bb%ba%e4%b8%80%e4%b8%aa%e4%b8%8d%e5%8f%97%e5%ae%89%e5%85%a8%e9%99%90%e5%88%b6%e7%9a%84-web-%e5%ba%94%e7%94%a8)
  - [2.3 配置 Spring Security](#23-%e9%85%8d%e7%bd%ae-spring-security)
  - [2.4 添加启动类](#24-%e6%b7%bb%e5%8a%a0%e5%90%af%e5%8a%a8%e7%b1%bb)
  - [2.5 测试](#25-%e6%b5%8b%e8%af%95)
  - [2.6 总结](#26-%e6%80%bb%e7%bb%93)
- [3. 核心配置解读](#3-%e6%a0%b8%e5%bf%83%e9%85%8d%e7%bd%ae%e8%a7%a3%e8%af%bb)
  - [3.1 功能介绍](#31-%e5%8a%9f%e8%83%bd%e4%bb%8b%e7%bb%8d)

<!-- /TOC -->

---

# 1 Spring Security Architecture Overview 核心组件

较为简单或者体量较小的技术, 完全可以参考着 demo 直接上手, 但系统的学习一门技术则不然. 以我的认知, 一般的文档大致有两种风格: 
- Architecture First - 致力于让读者先了解整体的架构, 方便我们对自己的认知有一个宏观的把控;
- Code First - 以特定的 demo 配合讲解, 可以让读者在解决问题的过程中顺便掌握一门技术;

学习一个体系的技术, 我推荐 Architecture First, 正如本文标题所言, 这篇文章是我 Spring Security 系列的第一篇, 主要是根据 Spring Security 文档选择性 ~~ 翻译 ~~ 整理而成的一个架构概览, 配合自己的一些注释方便大家理解. 参考版本为 Spring Security 4.2.3.RELEASE. 

这一节主要介绍一些在 Spring Security 中常见且核心的 Java 类, 它们之间的依赖, 构建起了整个框架. 想要理解整个架构, 最起码得对这些类眼熟.

## 1.1 SecurityContextHolder

`SecurityContextHolder` 用于存储安全上下文 (security context) 的信息. 当前操作的用户是谁, 该用户是否已经被认证, 他拥有哪些角色权.... 这些都被保存在 `SecurityContextHolder` 中. `SecurityContextHolder` 默认使用 `ThreadLocal` 策略来存储认证信息. 看到 `ThreadLocal` 也就意味着, 这是一种与 **线程** 绑定的策略. Spring Security 在用户登录时自动绑定认证信息到当前线程, 在用户退出时, 自动清除当前线程的认证信息. 但这一切的前提, 是你在 web 场景下使用 Spring Security, 而如果是 Swing 界面, Spring 也提供了支持, `SecurityContextHolder` 的策略则需要被替换, 鉴于我的初衷是基于 web 来介绍 Spring Security, 所以这里以及后续, 非 web 的相关的内容都一笔带过.  

### 获取当前用户的信息

因为身份信息是与线程绑定的, 所以可以在程序的任何地方使用静态方法获取用户信息. 一个典型的获取当前登录用户的姓名的例子如下所示:

```java
Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
if (principal instanceof UserDetails) {
     String username = ((UserDetails) principal).getUsername();
} else {
    String username = principal.toString();
}
```

`getAuthentication()` 返回了认证信息, 再次 `getPrincipal()` 返回了身份信息, `UserDetails` 便是 Spring 对身份信息封装的一个接口. `Authentication` 和 `UserDetails` 的介绍在下面的小节具体讲解, 本节重要的内容是介绍 `SecurityContextHolder` 这个容器.

## 1.2 Authentication

先看看这个接口的源码长什么样:

```java
package org.springframework.security.core;  // <1>

public interface Authentication extends Principal, Serializable {

	Collection<? extends GrantedAuthority> getAuthorities();    // <2>

	Object getCredentials();    // <2>

	Object getDetails();    // <2>

	Object getPrincipal();  // <2>

	boolean isAuthenticated(); // <2>

	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```

1. `Authentication` 是 spring security 包中的接口, 直接继承自 Principal 类, 而 Principal 是位于 `java.security` 包中的. 可以见得, `Authentication` 在 spring security 中是最高级别的 身份/认证 的抽象.

2. 由这个顶级接口, 我们可以得到用户拥有的权限信息列表, 密码, 用户细节信息, 用户身份信息, 认证信息. 


还记得 [1.1](#11-securitycontextholder) 节中, `authentication.getPrincipal()` 返回了一个 `Object`, 我们将 `Principal` 强转成了 Spring Security 中最常用的 `UserDetails`, 这在 Spring Security 中非常常见, 接口返回 `Object`, 使用 `instanceof` 判断类型, 强转成对应的具体实现类.   

接口详细解读如下:

- `getAuthorities()` [权限信息列表], 默认是 `GrantedAuthority` 接口的一些实现类, 通常是代表权限信息的一系列字符串.  
- `getCredentials()` [密码信息], 用户输入的密码字符串, 在认证过后通常会被移除, 用于保障安全. 
- `getDetails()` [细节信息], web 应用中的实现接口通常为 `WebAuthenticationDetails`, 它记录了访问者的 ip 地址和 sessionId 的值.
- `getPrincipal()` [最重要的**身份信息**], 大部分情况下返回的是 `UserDetails` 接口的实现类, 也是框架中的常用接口之一. UserDetails 接口将会在下面的小节重点介绍.

### Spring Security 是如何完成身份认证的

1. 用户名和密码被过滤器获取到, 封装成 `Authentication`, 通常情况下是 `UsernamePasswordAuthenticationToken` 这个实现类.  
2. `AuthenticationManager` 身份管理器负责验证这个 `Authentication`.  
3. 认证成功后, `AuthenticationManager` 身份管理器返回一个被填充满了信息的 (包括上面提到的权限信息, 身份信息, 细节信息, 但密码通常会被移除) `Authentication` 实例.
4. `SecurityContextHolder` 安全上下文容器将第 3 步填充了信息的 `Authentication`, 通过 `SecurityContextHolder.getContext().setAuthentication(...)` 方法, 设置到其中.  

这是一个抽象的认证流程, 而整个过程中, 如果不纠结于细节, 其实只剩下一个 `AuthenticationManager` 是我们没有接触过的了, 这个身份管理器我们在后面的小节介绍. 

将上述的流程转换成代码, 便是如下的流程:

```java
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
```

> 注意: 上述这段代码只是为了让大家了解 Spring Security 的工作流程而写的, 不是什么源码. 在实际使用中, 整个流程会变得更加的复杂, 但是基本思想, 和上述代码如出一辙.

## 1.3 AuthenticationManager

初次接触 Spring Security 的朋友相信会被 `AuthenticationManager`, `ProviderManager`, `AuthenticationProvider`... 这么多相似的 Spring 认证类搞得晕头转向, 但只要稍微梳理一下就可以理解清楚它们的联系和设计者的用意.   
`AuthenticationManager` (接口) 是认证相关的核心接口, 也是发起认证的出发点, 因为在实际需求中, 我们可能会允许用户使用 *'用户名 + 密码'* 登录, 同时允许用户使用 *'邮箱 + 密码'*, *'手机号码 + 密码'* 登录, 甚至, 可能允许用户使用 *'指纹'* 登录, 所以说 `AuthenticationManager` 一般不直接认证, AuthenticationManager 接口的常用实现类 `ProviderManager` 内部会维护一个 `List<AuthenticationProvider>` 列表, 存放多种认证方式, 实际上这是委托者模式的应用 (*Delegate*). 也就是说, 核心的认证入口始终只有一个: `AuthenticationManager`, 不同的认证方式: *用户名 + 密码* (`UsernamePasswordAuthenticationToken`), *邮箱 + 密码*, *手机号码 + 密码* 登录则对应了三个 `AuthenticationProvider`. 这样一来四不四就好理解多了? 熟悉 shiro 的朋友可以把 `AuthenticationProvider` 理解成 `Realm`. 在默认策略下, 只需要通过一个 `AuthenticationProvider` 的认证, 即可被认为是登录成功.

只保留了关键认证部分的 `ProviderManager` 源码:

```java
public class ProviderManager implements AuthenticationManager, MessageSourceAware,
		InitializingBean {
    
    // 维护一个 AuthenticationProvider 列表
	private List<AuthenticationProvider> providers = Collections.emptyList();

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		Class<? extends Authentication> toTest = authentication.getClass();
		AuthenticationException lastException = null;
		Authentication result = null;

        // 依次认证
		for (AuthenticationProvider provider : getProviders()) {
			if (!provider.supports(toTest)) {
				continue;
			}

			try {
				result = provider.authenticate(authentication);

				if (result != null) {
					copyDetails(authentication, result);
					break;
				}
			} catch (AuthenticationException e) {
				lastException = e;
			}
		}
        // 如果有 Authentication 信息, 则直接返回
		if (result != null) {
			if (eraseCredentialsAfterAuthentication
					&& (result instanceof CredentialsContainer)) {
				// 移除秘密
				((CredentialsContainer) result).eraseCredentials();
			}

            // 发布登录成功事件
			eventPublisher.publishAuthenticationSuccess(result);
			return result;
		}

		// 执行到此, 说名没有认证成功, 包装异常信息
		if (lastException == null) {
			lastException = new ProviderNotFoundException(messages.getMessage(
					"ProviderManager.providerNotFound",
					new Object[] { toTest.getName() },
					"No AuthenticationProvider found for {0}"));
		}
		prepareException(lastException, authentication);
		throw lastException;
	}
}
```

`ProviderManager` 中的 `List`, 会依照次序去认证, 认证成功则立即返回, 若认证失败则返回 `null`, 下一个 `AuthenticationProvider` 会继续尝试认证, 如果所有认证器都无法认证成功, 则 `ProviderManager` 会抛出一个 `ProviderNotFoundException` 异常.

到这里, 如果不纠结于 `AuthenticationProvider` 的实现细节以及安全相关的过滤器, 认证相关的核心类其实都已经介绍完毕了: 
    
- 身份信息的存放容器 `SecurityContextHolder`;
- 身份信息的抽象 `Authentication`;
- 身份认证器 `AuthenticationManager`;
- 认证流程; 

下面来介绍下 `AuthenticationProvider` 接口的具体实现.

## 1.4 DaoAuthenticationProvider

`AuthenticationProvider` 最最最常用的一个实现便是 `DaoAuthenticationProvider`. 顾名思义, Dao 正是数据访问层的缩写, 也暗示了这个身份认证器的实现思路. 由于本文是一个 Overview, 姑且只给出其 UML 类图:

![DaoAuthenticationProvider UML](https://raw.githubusercontent.com/ChuanShenLive/development_notes/master/Spring/spring-security-architecture/images/CP1-1-4_DaoAuthenticationProvider_UML.png?raw=true)

按照我们最直观的思路, 怎么去认证一个用户呢? 用户前台提交了用户名和密码, 而数据库中保存了用户名和密码, 认证便是负责比对同一个用户名, 提交的密码和保存的密码是否相同便是了. 

在 Spring Security 中, 提交的用户名和密码被封装成了 `UsernamePasswordAuthenticationToken`, 而根据用户名加载用户的任务则是交给了 `UserDetailsService`, 在 `DaoAuthenticationProvider` 中, 对应的方法便是 `retrieveUser`, 虽然有两个参数, 但是 `retrieveUser` 只有第一个参数起主要作用, 返回一个 `UserDetails`. 还需要完成 `UsernamePasswordAuthenticationToken` 和 `UserDetails` 密码的比对, 这便是交给 `additionalAuthenticationChecks` 方法完成的, 如果这个 `void` 方法没有抛异常, 则认为比对成功. 比对密码的过程, 用到了 `PasswordEncoder` 和 `SaltSource`, 密码加密和盐的概念相信不用我赘述了, 它们为保障安全而设计, 都是比较基础的概念.

如果你已经被这些概念搞得晕头转向了, 不妨这么理解 `DaoAuthenticationProvider`: 它获取用户提交的用户名和密码, 比对其正确性, 如果正确, 返回一个数据库中的用户信息 (假设用户信息被保存在数据库中).

## 1.5 UserDetails 与 UserDetailsService

上面不断提到了 UserDetails 这个接口, 它代表了最详细的用户信息, 这个接口涵盖了一些必要的用户信息字段, 具体的实现类对它进行了扩展.

```java
public interface UserDetails extends Serializable {

	Collection<? extends GrantedAuthority> getAuthorities();

	String getPassword();

	String getUsername();

	boolean isAccountNonExpired();

	boolean isAccountNonLocked();

	boolean isCredentialsNonExpired();

	boolean isEnabled();
}
```

它和 `Authentication` 接口很类似, 比如它们都拥有 `username`, `authorities` 区分他们也是本文的重点内容之一. `Authentication` 的 `getCredentials()` 与 `UserDetails` 中的 `getPassword()` 需要被区分对待, 前者是用户提交的密码凭证, 后者是用户正确的密码, 认证器其实就是对这两者的比对. `Authentication` 中的 `getAuthorities()` 实际是由 `UserDetails` 的 `getAuthorities()` 传递而形成的. 还记得 `Authentication` 接口中的 `getUserDetails()` 方法吗? 其中的 `UserDetails` 用户详细信息便是经过了 `AuthenticationProvider` 之后被填充的.

```java
package org.springframework.security.core.userdetails;

public interface UserDetailsService {
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

`UserDetailsService` 和 `AuthenticationProvider` 两者的职责常常被人们搞混, 关于他们的问题在文档的 FAQ 和 issues 中屡见不鲜. 记住一点即可, **`UserDetailsService` 只负责从特定的地方 (通常是数据库) 加载用户信息**, 仅此而已, 记住这一点, 可以避免走很多弯路. `UserDetailsService` 常见的实现类有 `JdbcDaoImpl`, `InMemoryUserDetailsManager`, 前者从数据库加载用户, 后者从内存中加载用户, 也可以自己实现 `UserDetailsService`, 通常这更加灵活.

## 1.6 架构概览图

为了更加形象的理解上述我介绍的这些核心类, 附上一张按照我的理解, 所画出 Spring Security 的一张非典型的 UML 图

![架构概览图 spring_security_architecture](https://raw.githubusercontent.com/ChuanShenLive/development_notes/master/Spring/spring-security-architecture/images/CP1-1-6_spring_security_architecture.png?raw=true)

如果对 Spring Security 的这些概念感到理解不能, 不用担心, 因为这是 Architecture First 导致的必然结果, 先过个眼熟. 后续的文章会秉持 Code First 的理念, 陆续详细地讲解这些实现类的使用场景, 源码分析, 以及最基本的: 如何配置 Spring Security, 在后面的文章中可以不时翻看这个章节, 找到具体的类在整个架构中所处的位置, 这也是本篇文章的定位. 另外, 一些 Spring Security 的过滤器还未囊括在架构概览中, 如将表单信息包装成 `UsernamePasswordAuthenticationToken` 的过滤器, 考虑到这些虽然也是架构的一部分, 但是真正重写他们的可能性较小, 所以打算放到后面的章节讲解.

---

# 2 Spring Security Guides

第一章 Spring Security Architecture Overview, 介绍了 Spring Security 的基础架构, 这一章通过 Spring 官方给出的一个 guides 例子, 来了解 Spring Security 是如何保护我们的应用的, 之后会对进行一个解读.

## 2.1 引入依赖

```xml
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
    </dependencies>
```

由于我们集成了 springboot, 所以不需要显示的引入 Spring Security 文档中描述 core, config 依赖, 只需要引入 `spring-boot-starter-security` 即可.

## 2.2 创建一个不受安全限制的 web 应用

这是一个首页, 不受安全限制

`src\main\resources\templates\home.html`

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity3"
      lang="en">
<head>
    <meta charset="UTF-8">
    <title>Spring Security Example</title>
</head>
<body>
    <h1>Welcome!</h1>

    <p>Click <a th:href="@{/hello}">here</a> to see a greeting.</p>
</body>
</html>
```

这个简单的页面上包含了一个链接, 跳转到 "/hello". 对应如下的页面

`src\main\resources\templates\hello.html`

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity3"
      lang="en">
<head>
    <meta charset="UTF-8">
    <title>Hello World!</title>
</head>
<body>
    <h1>Hello World!</h1>
</body>
</html>
```

接下来配置 Spring MVC, 使得我们能够访问到页面.

`src\main\java\com\chuanshen\config\MvcConfig.java`

```java
@Configuration
public class MvcConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/home").setViewName("home");
        registry.addViewController("/").setViewName("home");
        registry.addViewController("/hello").setViewName("hello");
        registry.addViewController("/login").setViewName("login");
    }
}
``` 

## 2.3 配置 Spring Security

一个典型的安全配置如下所示:

`src\main\java\com\chuanshen\config\WebSecurityConfig.java`

```java
@Configuration
@EnableWebSecurity  // <1>
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {   // <1>

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    // <2>
                .authorizeRequests()
                    .antMatchers("/", "/home").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .and()
                .logout()
                    .permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth    // <3>
                .inMemoryAuthentication()
                    .withUser("admin").password("admin").roles("USER");
    }
}
```

1. `@EnableWebSecurity` 注解使得 SpringMVC 集成了 Spring Security 的 web 安全支持. 另外, `WebSecurityConfig` 配置类同时继承了 `WebSecurityConfigurerAdapter`, 重写了其中的特定方法, 用于自定义 Spring Security 配置. 整个 Spring Security 的工作量, 其实都是集中在该配置类, 不仅仅是这个 guides, 实际项目中也是如此.

2. `configure(HttpSecurity)` 定义了哪些 URL 路径应该被拦截, 如字面意思所描述: "/",  "/home" 允许所有人访问, "/login" 作为登录入口, 也被允许访问, 而剩下的 "/hello" 则需要登陆后才可以访问.

3. `configure(AuthenticationManagerBuilder)` 在内存中配置一个用户, admin/admin 分别是用户名和密码, 这个用户拥有 USER 角色。

我们目前还没有登录页面, 下面创建登录页面:

`src\main\resources\templates\login.html`

```html
<!DOCTYPE html>
<html mlns="http://www.w3.org/1999/xhtml"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity3"
      lang="en">
<head>
    <meta charset="UTF-8">
    <title>Spring Security Example </title>
</head>
<body>
    <div th:if="${param.error}">
        Invalid username and password.
    </div>
    <div th:if="${param.logout}">
        You have been logged out.
    </div>
    <form th:action="@{/login}" method="post">
        <div><label> User Name : <input type="text" name="username"/> </label></div>
        <div><label> Password: <input type="password" name="password"/> </label></div>
        <div><input type="submit" value="Sign In"/></div>
    </form>
</body>
</html>
```

这个 Thymeleaf 模板提供了一个用于提交用户名和密码的表单, 其中 name="username", name="password" 是默认的表单值, 并发送到 "/ login". 在默认配置中, Spring Security 提供了一个拦截该请求并验证用户的过滤器. 如果验证失败, 该页面将重定向到"/ login?error", 并显示相应的错误消息. 当用户选择注销, 请求会被发送到"/ login?logout".

最后, 我们为 `hello.html` 添加一些内容, 用于展示用户信息.

`src\main\resources\templates\hello.html`

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity3"
      lang="en">
<head>
    <meta charset="UTF-8">
    <title>Hello World!</title>
</head>
<body>
    <h1 th:inline="text">Hello [[${#httpServletRequest.remoteUser}]]!</h1>
    <form th:action="@{/logout}" method="post">
        <input type="submit" value="Sign Out">
    </form>
</body>
</html>
```

我们使用 Spring Security 之后, `HttpServletRequest#getRemoteUser()` 可以用来获取用户名. 登出请求将被发送到"/logout". 成功注销后, 会将用户重定向到"/login?logout".

## 2.4 添加启动类

`src\main\java\com\chuanshen\SpringSecurityArchitectureDemoApplication.java`

```java
@SpringBootApplication
public class SpringSecurityArchitectureDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityArchitectureDemoApplication.class, args);
    }

}
```

## 2.5 测试

访问首页 [http://localhost:8080/](http://localhost:8080/).

![home.html](https://raw.githubusercontent.com/ChuanShenLive/development_notes/master/Spring/spring-security-architecture/images/CP2-2-5_home.png?raw=true)

点击 here, 尝试访问受限的页面: /hello, 由于未登录, 结果被强制跳转到登录也 /login.

![login.html](https://raw.githubusercontent.com/ChuanShenLive/development_notes/master/Spring/spring-security-architecture/images/CP2-2-5_login.png?raw=true)

输入正确的用户名和密码之后, 跳转到之前想要访问的 /hello.

![hello.html](https://raw.githubusercontent.com/ChuanShenLive/development_notes/master/Spring/spring-security-architecture/images/CP2-2-5_hello.png?raw=true)

点击 Sign out 退出按钮, 访问: /logout, 回到登录页面.

![logout.html](https://raw.githubusercontent.com/ChuanShenLive/development_notes/master/Spring/spring-security-architecture/images/CP2-2-5_logout.png?raw=true)

## 2.6 总结

本篇文章没有什么干货, 基本算是翻译了 Spring Security Guides 的内容, 稍微了解 Spring Security 的朋友都不会对这个翻译感到陌生. 考虑到受众的问题, 一个入门的例子是必须得有的, 方便后续对 Spring Security 的自定义配置进行讲解. 下一节, 以此 guides 为例, 讲解这些最简化的配置背后, Spring Security 都帮我们做了什么工作.

# 3. 核心配置解读

上一章 Spring Security Guides 通过 Spring Security 的配置项了解了 Spring Security 是如何保护我们的应用的, 本章对上一次的配置做一个分析.

## 3.1 功能介绍

```java 
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/", "/home").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .and()
                .logout()
                    .permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                    .withUser("admin").password("admin").roles("USER");
    }
}
```
---