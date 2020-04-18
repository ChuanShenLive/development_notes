
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
- [3. Spring Security 核心配置解读](#3-spring-security-%e6%a0%b8%e5%bf%83%e9%85%8d%e7%bd%ae%e8%a7%a3%e8%af%bb)
	- [3.1 功能介绍](#31-%e5%8a%9f%e8%83%bd%e4%bb%8b%e7%bb%8d)
	- [3.2 @EnableWebSecurity](#32-enablewebsecurity)
		- [WebSecurityConfiguration](#websecurityconfiguration)
		- [AuthenticationConfiguration](#authenticationconfiguration)
	- [3.3 WebSecurityConfigurerAdapter](#33-websecurityconfigureradapter)
		- [HttpSecurity 常用配置](#httpsecurity-%e5%b8%b8%e7%94%a8%e9%85%8d%e7%bd%ae)
		- [WebSecurityBuilder](#websecuritybuilder)
		- [AuthenticationManagerBuilder](#authenticationmanagerbuilder)
- [4 Spring Security 核心过滤器源码分析](#4-spring-security-%e6%a0%b8%e5%bf%83%e8%bf%87%e6%bb%a4%e5%99%a8%e6%ba%90%e7%a0%81%e5%88%86%e6%9e%90)
	- [4.1 核心过滤器概述](#41-%e6%a0%b8%e5%bf%83%e8%bf%87%e6%bb%a4%e5%99%a8%e6%a6%82%e8%bf%b0)
	- [4.2 SecurityContextPersistenceFilter](#42-securitycontextpersistencefilter)
		- [源码分析](#%e6%ba%90%e7%a0%81%e5%88%86%e6%9e%90)
	- [4.3 UsernamePasswordAuthenticationFilter](#43-usernamepasswordauthenticationfilter)
		- [源码分析](#%e6%ba%90%e7%a0%81%e5%88%86%e6%9e%90-1)
	- [4.4 AnonymousAuthenticationFilter](#44-anonymousauthenticationfilter)
		- [源码分析](#%e6%ba%90%e7%a0%81%e5%88%86%e6%9e%90-2)
	- [4.5 ExceptionTranslationFilter](#45-exceptiontranslationfilter)
		- [源码分析](#%e6%ba%90%e7%a0%81%e5%88%86%e6%9e%90-3)
	- [4.6 FilterSecurityInterceptor](#46-filtersecurityinterceptor)
	- [总结](#%e6%80%bb%e7%bb%93)
	- [本章在介绍过滤器时, 顺便进行了一些源码的分析, 目的是方便理解整个 Spring Security 的工作流. 伴随着整个过滤器链的介绍, 安全框架的轮廓应该已经浮出水面了, 下面的章节, 主要打算通过自定义一些需求, 再次分析其他组件的源码, 学习应该如何改造 Spring Security, 为我们所用.](#%e6%9c%ac%e7%ab%a0%e5%9c%a8%e4%bb%8b%e7%bb%8d%e8%bf%87%e6%bb%a4%e5%99%a8%e6%97%b6-%e9%a1%ba%e4%be%bf%e8%bf%9b%e8%a1%8c%e4%ba%86%e4%b8%80%e4%ba%9b%e6%ba%90%e7%a0%81%e7%9a%84%e5%88%86%e6%9e%90-%e7%9b%ae%e7%9a%84%e6%98%af%e6%96%b9%e4%be%bf%e7%90%86%e8%a7%a3%e6%95%b4%e4%b8%aa-spring-security-%e7%9a%84%e5%b7%a5%e4%bd%9c%e6%b5%81-%e4%bc%b4%e9%9a%8f%e7%9d%80%e6%95%b4%e4%b8%aa%e8%bf%87%e6%bb%a4%e5%99%a8%e9%93%be%e7%9a%84%e4%bb%8b%e7%bb%8d-%e5%ae%89%e5%85%a8%e6%a1%86%e6%9e%b6%e7%9a%84%e8%bd%ae%e5%bb%93%e5%ba%94%e8%af%a5%e5%b7%b2%e7%bb%8f%e6%b5%ae%e5%87%ba%e6%b0%b4%e9%9d%a2%e4%ba%86-%e4%b8%8b%e9%9d%a2%e7%9a%84%e7%ab%a0%e8%8a%82-%e4%b8%bb%e8%a6%81%e6%89%93%e7%ae%97%e9%80%9a%e8%bf%87%e8%87%aa%e5%ae%9a%e4%b9%89%e4%b8%80%e4%ba%9b%e9%9c%80%e6%b1%82-%e5%86%8d%e6%ac%a1%e5%88%86%e6%9e%90%e5%85%b6%e4%bb%96%e7%bb%84%e4%bb%b6%e7%9a%84%e6%ba%90%e7%a0%81-%e5%ad%a6%e4%b9%a0%e5%ba%94%e8%af%a5%e5%a6%82%e4%bd%95%e6%94%b9%e9%80%a0-spring-security-%e4%b8%ba%e6%88%91%e4%bb%ac%e6%89%80%e7%94%a8)

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

![DaoAuthenticationProvider UML](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP1-1-4_DaoAuthenticationProvider_UML.png?raw=true)

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

![架构概览图 spring_security_architecture](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP1-1-6_spring_security_architecture.png?raw=true)

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


![home.html](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP2-2-5_home.png?raw=true)

点击 here, 尝试访问受限的页面: /hello, 由于未登录, 结果被强制跳转到登录也 /login.


![login.html](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP2-2-5_login.png?raw=true)

输入正确的用户名和密码之后, 跳转到之前想要访问的 /hello.


![hello.html](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP2-2-5_hello.png?raw=true)

点击 Sign out 退出按钮, 访问: /logout, 回到登录页面.

![logout.html](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP2-2-5_logout.png?raw=true)

## 2.6 总结

本篇文章没有什么干货, 基本算是翻译了 Spring Security Guides 的内容, 稍微了解 Spring Security 的朋友都不会对这个翻译感到陌生. 考虑到受众的问题, 一个入门的例子是必须得有的, 方便后续对 Spring Security 的自定义配置进行讲解. 下一节, 以此 guides 为例, 讲解这些最简化的配置背后, Spring Security 都帮我们做了什么工作.

---

# 3. Spring Security 核心配置解读

上一章 Spring Security Guides 通过 Spring Security 的配置项了解了 Spring Security 是如何保护我们的应用的, 本章对上一次的配置做一个分析.

## 3.1 功能介绍

这是 Spring Security 入门指南中的配置项:

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

当配置了上述的 javaconfig 之后, 我们的应用便具备了如下的功能:  

- 除了 `"/"`, `"/home"`(首页), `"/login"`(登录), `"/logout"`(注销) 之外, 其他路径都需要认证.
- 指定 `"/login"` 该路径为登录页面, 当未认证的用户尝试访问任何受保护的资源时, 都会跳转到 `"/login"`.
- 默认指定 `"/logout"` 为注销页面
- 配置一个内存中的用户认证器, 使用 admin/admin 作为用户名和密码, 具有 USER 角色
- 防止 CSRF 攻击
- Session Fixation protection (可以参考 Spring Session 的文章, 防止别人篡改 sessionId)
- Security Header (添加一系列和 Header 相关的控制)
  - HTTP Strict Transport Security for secure requests
  - 集成 X-Content-Type-Options
  - 缓存控制
  - 集成 X-XSS-Protection
  - X-Frame-Options integration to help prevent Clickjacking (iframe 被默认禁止使用)
- 为 Servlet API 集成了如下的几个方法
  - HttpServletRequest.html#getRemoteUser()
  - HttpServletRequest.html#getUserPrincipal()
  - HttpServletRequest.html#isUserInRole(java.lang.String)
  - HttpServletRequest.html#login(java.lang.String, java.lang.String)
  - HttpServletRequest.html#logout()

## 3.2 @EnableWebSecurity

我们自己定义的配置类 `WebSecurityConfig` 加上了 `@EnableWebSecurity` 注解, 同时继承了 `WebSecurityConfigurerAdapter`. 你可能会在想谁的作用大一点, 毫无疑问 `@EnableWebSecurity` 起到决定性的配置作用, 它其实是个组合注解.

```java
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented
@Import({ WebSecurityConfiguration.class,   // <2>
		SpringWebMvcImportSelector.class,   // <1>
		OAuth2ImportSelector.class })
@EnableGlobalAuthentication // <3>
@Configuration
public @interface EnableWebSecurity {
	boolean debug() default false;
}
```

`@Import` 是 spring boot 提供的用于引入外部的配置的注解, 可以理解为: `@EnableWebSecurity` 注解激活了 `@Import` 注解中包含的配置类.

1. `SpringWebMvcImportSelector` 的作用是判断当前的环境是否包含 spring mvc, 因为 spring security 可以在非 spring 环境下使用, 为了避免 DispatcherServlet 的重复配置, 所以使用了这个注解来区分.
2. `WebSecurityConfiguration` 顾名思义, 是用来配置 web 安全的, 下面的小节会详细介绍。
3. `@EnableGlobalAuthentication` 注解的源码如下:

```java
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented
@Import(AuthenticationConfiguration.class)
@Configuration
public @interface EnableGlobalAuthentication {
}
```

注意点同样在 `@Import` 之中, 它实际上激活了 `AuthenticationConfiguration` 这样的一个配置类, 用来配置认证相关的核心类.

也就是说: `@EnableWebSecurity` 完成的工作便是加载了 `WebSecurityConfiguration`,`AuthenticationConfiguration` 这两个核心配置类, 也就此将 spring security 的职责划分为了配置安全信息, 配置认证信息两部分.

### WebSecurityConfiguration

在这个配置类中, 有一个非常重要的 Bean 被注册了.

```java
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {

    //...

	/**
	 * Creates the Spring Security Filter Chain
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 */
	// DEFAULT_FILTER_NAME = "springSecurityFilterChain"
    @Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasConfigurers = webSecurityConfigurers != null
				&& !webSecurityConfigurers.isEmpty();
		if (!hasConfigurers) {
			WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			webSecurity.apply(adapter);
		}
		return webSecurity.build();
	}

    // ...
}
```

在未使用 spring boot 之前, 大多数人都应该对 `springSecurityFilterChain` 这个名词不会陌生, 他是 spring security 的核心过滤器, 是整个认证的入口. 在曾经的 XML 配置中, 想要启用 spring security, 需要在 `web.xml` 中进行如下配置:

```xml
<!-- Spring Security -->
   <filter>
       <filter-name>springSecurityFilterChain</filter-name>
       <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
   </filter>

   <filter-mapping>
       <filter-name>springSecurityFilterChain</filter-name>
       <url-pattern>/*</url-pattern>
   </filter-mapping>
```

而在 spring boot 集成之后, 这样的 XML 被 java 配置取代. `WebSecurityConfiguration` 中完成了声明 `springSecurityFilterChain` 的作用, 并且最终交给 `DelegatingFilterProxy` 这个代理类, 负责拦截请求 (注意 `DelegatingFilterProxy` 这个类不是 spring security 包中的, 而是存在于 web 包中, spring 使用了代理模式来实现安全过滤的解耦).

### AuthenticationConfiguration

```java
@Configuration(proxyBeanMethods = false)
@Import(ObjectPostProcessorConfiguration.class)
public class AuthenticationConfiguration {

    // ...
	@Bean
	public AuthenticationManagerBuilder authenticationManagerBuilder(
			ObjectPostProcessor<Object> objectPostProcessor, ApplicationContext context) {
		LazyPasswordEncoder defaultPasswordEncoder = new LazyPasswordEncoder(context);
		AuthenticationEventPublisher authenticationEventPublisher = getBeanOrNull(context, AuthenticationEventPublisher.class);

		DefaultPasswordEncoderAuthenticationManagerBuilder result = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor, defaultPasswordEncoder);
		if (authenticationEventPublisher != null) {
			result.authenticationEventPublisher(authenticationEventPublisher);
		}
		return result;
	}

	public AuthenticationManager getAuthenticationManager() throws Exception {
        // ...
	}
    //...
}
```

`AuthenticationConfiguration` 的主要任务, 便是负责生成全局的身份认证管理者 AuthenticationManager. 还记得在 "1 Spring Security Architecture Overview 核心组件", 介绍了 Spring Security 的认证体系, `AuthenticationManager` 便是最核心的身份认证管理器.

## 3.3 WebSecurityConfigurerAdapter

适配器模式在 spring 中被广泛的使用, 在配置中使用 Adapter 的好处便是, 我们可以选择性的配置想要修改的那一部分配置, 而不用覆盖其他不相关的配置. `WebSecurityConfigurerAdapter` 中我们可以选择自己想要修改的内容, 来进行重写, 而其提供了三个 configure 重载方法, 是我们主要关心的:

![WebSecurityConfigurerAdapter 中的 configure](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP3-3-3_WebSecurityConfigurerAdapter.png?raw=true)

由参数就可以知道, 分别是对 `AuthenticationManagerBuilder`, `WebSecurity`, `HttpSecurity` 进行个性化的配置.

### HttpSecurity 常用配置

```java
@Configuration
@EnableWebSecurity
public class CustomWebSecurityConfig extends WebSecurityConfigurerAdapter {
  
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/resources/**", "/signup", "/about").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .usernameParameter("username")
                .passwordParameter("password")
                .failureForwardUrl("/login?error")
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/index")
                .permitAll()
                .and()
            .httpBasic()
                .disable();
    }
}
```

上述是一个使用 Java Configuration 配置 `HttpSecurity` 的典型配置, 其中 http 作为根开始配置, 每一个 `and()` 对应了一个模块的配置 (等同于 xml 配置中的结束标签), 并且 `and()` 返回了 `HttpSecurity` 本身, 于是可以连续进行配置. 他们配置的含义也非常容易通过变量本身来推测:

- `authorizeRequests()` 配置路径拦截, 表明路径访问所对应的权限, 角色, 认证信息.
- `formLogin()` 对应表单认证相关的配置
- `logout()` 对应了注销相关的配置
- `httpBasic()` 可以配置 basic 登录
- etc

他们分别代表了 http 请求相关的安全配置, 这些配置项无一例外的返回了 Configurer 类, 而所有的 http 相关配置可以通过查看 HttpSecurity 的主要方法得知:

![HttpSecurity 中的主要方法](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP3-3-3_HttpSecurity.png?raw=true)

需要对 http 协议有一定的了解才能完全掌握所有的配置, 不过, spring boot 和 spring security 的自动配置已经足够使用了. 其中每一项 Configurer (e.g. `FormLoginConfigurer`, `CsrfConfigurer`) 都是 `HttpConfigurer` 的细化配置项.

### WebSecurityBuilder

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
            .ignoring()
            .antMatchers("/resources/**");
    }
}
```

上述是一个使用 Java Configuration 配置 `WebSecurity` 的典型配置, 这个配置中并不会出现太多的配置信息.

### AuthenticationManagerBuilder

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
            .withUser("admin").password("admin").roles("USER");
    }
}
```

想要在 `WebSecurityConfigurerAdapter` 中进行认证相关的配置, 可以使用 `configure(AuthenticationManagerBuilder auth)` 暴露一个 `AuthenticationManager` 的建造器: `AuthenticationManagerBuilder`. 如上所示, 我们便完成了内存中用户的配置.

`WebSecurityConfigurerAdapter` 也可以如下配置:

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("admin").password("admin").roles("USER");
    }
}
```

如果你的应用只有唯一一个 `WebSecurityConfigurerAdapter`, 那么他们之间的差距可以被忽略.

从方法名可以看出两者的区别: 使用 `@Autowired` 注入的 `AuthenticationManagerBuilder` 是全局的身份认证器, 作用域可以跨越多个 `WebSecurityConfigurerAdapter`, 以及影响到基于 `Method` 的安全控制; 而 `protected configure()` 的方式则类似于一个匿名内部类, 它的作用域局限于一个 `WebSecurityConfigurerAdapter` 内部. 关于这一点的区别, 可以参考 [issuespring-security#issues4571](https://github.com/spring-projects/spring-security/issues/4571). 官方文档中, 也给出了配置多个 `WebSecurityConfigurerAdapter` 的场景以及 demo, 将在该系列的后续文章中解读.

---

# 4 Spring Security 核心过滤器源码分析

前面的部分, 我们关注了 Spring Security 是如何完成认证工作的, 但是另外一部分核心的内容: 过滤器一直没有提到, 我们已经知道 Spring Security 使用了 springSecurityFillterChian 作为了安全过滤的入口, 这一节主要分析一下这个过滤器链都包含了哪些关键的过滤器, 并且各自的使命是什么.

## 4.1 核心过滤器概述

由于过滤器链路中的过滤较多, 即使是 Spring Security 的官方文档中也并未对所有的过滤器进行介绍, 在之前, "Spring Security Guides" 入门指南中我们配置了一个表单登录的 demo, 以此为例, 来看看这过程中 Spring Security 都帮我们自动配置了哪些过滤器.

```
Creating filter chain: any request, [
    org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@4beaf6bd, 
    org.springframework.security.web.context.SecurityContextPersistenceFilter@336206d8, 
    org.springframework.security.web.header.HeaderWriterFilter@1f0b3cfe, 
    org.springframework.security.web.csrf.CsrfFilter@2b03d52f, 
    org.springframework.security.web.authentication.logout.LogoutFilter@46185a1b, 
    org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@6eb17ec8, 
    org.springframework.security.web.savedrequest.RequestCacheAwareFilter@1f11f64e, 
    org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@4068102e, 
    org.springframework.security.web.authentication.AnonymousAuthenticationFilter@6b2e46af, 
    org.springframework.security.web.session.SessionManagementFilter@65a48602, 
    org.springframework.security.web.access.ExceptionTranslationFilter@42ea287, 
    org.springframework.security.web.access.intercept.FilterSecurityInterceptor@5633ed82 ]
```

上述的 log 信息是从 spring boot 启动的日志中 CV 所得, spring security 的过滤器日志有一个特点: log 打印顺序与实际配置顺序符合, 也就意味着 `SecurityContextPersistenceFilter` 是整个过滤器链的第一个过滤器, 而 `FilterSecurityInterceptor` 则是末置的过滤器. 另外通过观察过滤器的名称和所在的包名, 可以大致地分析出他们各自的作用, 如 `UsernamePasswordAuthenticationFilter` 明显便是与使用用户名和密码登录相关的过滤器, 而 `FilterSecurityInterceptor` 我们似乎看不出它的作用, 但是其位于 `web.access` 包下, 大致可以分析出他与访问限制相关. 第4章主要就是介绍这些常用的过滤器, 对其中关键的过滤器进行一些源码分析. 

先大致介绍下每个过滤器的作用:


- **`SecurityContextPersistenceFilter`** 两个主要职责:
  - 请求来临时, 创建 `SecurityContext` 安全上下文信息;
  - 请求结束时清空 `SecurityContextHolder`;
- `HeaderWriterFilter` (文档中并未介绍, 非核心过滤器) 用来给 http 响应添加一些 Header, 比如 X-Frame-Options, X-XSS-Protection*, X-Content-Type-Options.
- `CsrfFilter` 在 spring5 这个版本中被默认开启的一个过滤器, 用于防止 csrf 攻击, 了解前后端分离的人一定不会对这个攻击方式感到陌生, 前后端使用 json 交互需要注意的一个问题.
- `LogoutFilter` 顾名思义, 处理注销的过滤器
- **`UsernamePasswordAuthenticationFilter`** 这个会重点分析, 表单提交了 username 和 password, 被封装成 token 进行一系列的认证, 便是主要通过这个过滤器完成的, 在表单认证的方法中, 这是最最关键的过滤器.
- `RequestCacheAwareFilter` (文档中并未介绍, 非核心过滤器) 内部维护了一个 RequestCache, 用于缓存 request 请求
- `SecurityContextHolderAwareRequestFilter` 此过滤器对 `ServletRequest` 进行了一次包装, 使得 request 具有更加丰富的 API
- **`AnonymousAuthenticationFilter`** 匿名身份过滤器, 这个过滤器个人认为很重要, 需要将它与 `UsernamePasswordAuthenticationFilter` 放在一起比较理解, spring security 为了兼容未登录的访问, 也走了一套认证流程, 只不过是一个匿名的身份.
- `SessionManagementFilter` 和 session 相关的过滤器, 内部维护了一个 SessionAuthenticationStrategy, 两者组合使用, 常用来防止 session-fixation protection attack, 以及限制同一用户开启多个会话的数量.
- **`ExceptionTranslationFilter`** 直译成异常翻译过滤器, 还是比较形象的, 这个过滤器本身不处理异常, 而是将认证过程中出现的异常交给内部维护的一些类去处理, 具体是那些类下面详细介绍.
- **`FilterSecurityInterceptor`** 这个过滤器决定了访问特定路径应该具备的权限, 访问的用户的角色, 权限是什么? 访问的路径需要什么样的角色和权限? 这些判断和处理都是由该类进行的.

其中加粗的过滤器可以被认为是 Spring Security 的核心过滤器, 将在下面, 一个过滤器对应一个小节来讲解.

## 4.2 SecurityContextPersistenceFilter

试想一下, 如果我们不使用 Spring Security, 如何保存用户信息呢, 大多数情况下会考虑使用 Session 对吧.   
在 Spring Security 中也是如此, 用户在登录过一次之后, 后续的访问便是通过 sessionId 来识别, 从而认为用户已经被认证. 具体在何处存放用户信息, 便是第一篇文章中提到的 `SecurityContextHolder`. 认证相关的信息是如何被存放到其中的, 便是通过 `SecurityContextPersistenceFilter`. 在 4.1 概述中也提到了, `SecurityContextPersistenceFilter` 的两个主要作用便是请求来临时, 创建 `SecurityContext` 安全上下文信息和请求结束时清空 `SecurityContextHolder`.   
顺带提一下: 微服务的一个设计理念需要实现服务通信的无状态, 而 http 协议中的无状态意味着**不允许存在 session**, 这可以通过 **`setAllowSessionCreation(false)`** 实现, 这并不意味着 `SecurityContextPersistenceFilter` 变得无用，因为它还需要**负责清除用户信息**.   
在 Spring Security 中, 虽然安全上下文信息被存储于 Session 中, 但我们在实际使用中不应该直接操作 Session, 而应当使用 SecurityContextHolder.

### 源码分析

`org.springframework.security.web.context.SecurityContextPersistenceFilter.java`

```java
public class SecurityContextPersistenceFilter extends GenericFilterBean {

	static final String FILTER_APPLIED = "__spring_security_scpf_applied";

    // 安全上下文存储的仓库
	private SecurityContextRepository repo;


	public SecurityContextPersistenceFilter() {
        // HttpSessionSecurityContextRepository 是 SecurityContextRepository 接口的一个实现类, 使用 HttpSession 来存储 SecurityContext.
		this(new HttpSessionSecurityContextRepository());
	}

	public SecurityContextPersistenceFilter(SecurityContextRepository repo) {
		this.repo = repo;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (request.getAttribute(FILTER_APPLIED) != null) {     // FILTER_APPLIED = "__spring_security_scpf_applied"
			// ensure that filter is only applied once per request 确保 对于每个 请求 scpf 只执行一次
			chain.doFilter(request, response);
			return;
		}

		request.setAttribute(FILTER_APPLIED, Boolean.TRUE); // 设置 scpf 的 FILTER_APPLIED 标签, 表示 Filter 已经执行过.

        // 包装 request, response
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
		// 从 Session 中获取安全上下文信息
        SecurityContext contextBeforeChainExecution = repo.loadContext(holder);

		try {
            // 请求开始时, 设置安全上下文信息, 这样就避免了用户直接从 Session 中获取安全上下文信息
			SecurityContextHolder.setContext(contextBeforeChainExecution);
			chain.doFilter(holder.getRequest(), holder.getResponse());
		}
		finally {
            // 请求结束后, 清空安全上下文信息
			SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
			// Crucial removal of SecurityContextHolder contents - do this before anything else.
			SecurityContextHolder.clearContext();
			repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
			request.removeAttribute(FILTER_APPLIED);
			if (debug) {
				logger.debug("SecurityContextHolder now cleared, as request processing completed");
			}
		}
	}
}
```

过滤器一般负责核心的处理流程, 而具体的业务实现, 通常交给其中聚合的其他实体类, 这在 Filter 的设计中很常见, 同时也符合职责分离模式.
例如存储安全上下文和读取安全上下文的工作完全委托给了 `HttpSessionSecurityContextRepository` 去处理, 而这个类中也有几个方法可以稍微解读下, 方便我们理解内部的工作流程.

`org.springframework.security.web.context.HttpSessionSecurityContextRepository.java`

```java
public class HttpSessionSecurityContextRepository implements SecurityContextRepository {
	
	// The default key under which the security context will be stored in the session. `SPRING_SECURITY_CONTEXT` 是安全上下文默认存储在 Session 中的键值.
	public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

	// SecurityContext instance used to check for equality with default (unauthenticated) content
	private final Object contextObject = SecurityContextHolder.createEmptyContext();
	private boolean allowSessionCreation = true;
	private boolean disableUrlRewriting = false;
	private String springSecurityContextKey = SPRING_SECURITY_CONTEXT_KEY;

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * Gets the security context for the current request (if available) and returns it.
	 * If the session is null, the context object is null or the context object stored in the session is not an instance of SecurityContext, 
     * a new context object will be generated and returned.
     * 从当前 request 中取出安全上下文, 如果 session 为空, 则会返回一个新的安全上下文.
	 */
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
		HttpServletRequest request = requestResponseHolder.getRequest();
		HttpServletResponse response = requestResponseHolder.getResponse();
		HttpSession httpSession = request.getSession(false);

		SecurityContext context = readSecurityContextFromSession(httpSession);

		if (context == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("No SecurityContext was available from the HttpSession: "
						+ httpSession + ". " + "A new one will be created.");
			}
			context = generateNewContext();

		}
        // ...
		return context;
	}
    // ...

    // 判断 request 中是否存在 context
	public boolean containsContext(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return false;
		}
		return session.getAttribute(springSecurityContextKey) != null;
	}


	 // param httpSession: the session obtained from the request.
	private SecurityContext readSecurityContextFromSession(HttpSession httpSession) {
		final boolean debug = logger.isDebugEnabled();
		if (httpSession == null) {
			if (debug) {
				logger.debug("No HttpSession currently exists");
			}
			return null;
		}

		// Session exists, so try to obtain a context from it. Session 存在的情况下, 尝试获取其中的 SecurityContext.
		Object contextFromSession = httpSession.getAttribute(springSecurityContextKey);
		if (contextFromSession == null) {
			if (debug) {
				logger.debug("HttpSession returned null object for SPRING_SECURITY_CONTEXT");
			}
			return null;
		}
        // ...
		return (SecurityContext) contextFromSession;
	}

	/**
	 * By default, callsSecurityContextHolder#createEmptyContext() to obtain a new context (there should be no context present in the holder when this method is
	 * called). Using this approach the context creation strategy is decided by the SecurityContextHolderStrategy in use. The default implementations will
	 * return a new SecurityContextImpl.
	 * 初次请求时创建一个新的 SecurityContext 实例
	 * @return a new SecurityContext instance. Never null.
	 */
	protected SecurityContext generateNewContext() {
		return SecurityContextHolder.createEmptyContext();
	}
    // ...
}
```

`SecurityContextPersistenceFilter` 和 `HttpSessionSecurityContextRepository` 配合使用, 构成了 Spring Security 整个调用链路的入口, 为什么将它放在最开始的地方也是显而易见的, 后续的过滤器中大概率会依赖 Session 信息和安全上下文信息.

## 4.3 UsernamePasswordAuthenticationFilter

表单认证是最常用的一个认证方式, 一个最直观的业务场景便是允许用户在表单中输入用户名和密码进行登录, 而这背后的 `UsernamePasswordAuthenticationFilter`, 在整个 Spring Security 的认证体系中则扮演着至关重要的角色.

![authentication 时序图](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP4-3-3_authentication_sequence_chart.jpg?raw=true)

上述的时序图, 可以看出 `UsernamePasswordAuthenticationFilter` 主要肩负起了调用身份认证器校验身份的作用, 至于认证的细节, 在前面几章花了很大篇幅进行了介绍, 到这里其实 Spring Security 的基本流程就已经走通了.

### 源码分析

`org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter#attemptAuthentication()`

```java
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    // ...
	public UsernamePasswordAuthenticationFilter() {
		super(new AntPathRequestMatcher("/login", "POST"));
	}

	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		if (postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException(
					"Authentication method not supported: " + request.getMethod());
		}

        // 获取表单中的用户名密码
		String username = obtainUsername(request);
		String password = obtainPassword(request);
        // ...
		username = username.trim();

        // 组装成 username + password 形式的 token
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
        // 交给内部的 AuthenticationManager 去认证, 并返回认证信息.
		return this.getAuthenticationManager().authenticate(authRequest);
	}
}
```

`UsernamePasswordAuthenticationFilter` 本身的代码只包含了上述这么一个方法, 非常简略, 而在其父类 `AbstractAuthenticationProcessingFilter` 中包含了大量的细节, 值得我们分析:

`org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter.java`

```java

public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean
		implements ApplicationEventPublisherAware, MessageSourceAware {
    
    // ...
    // 包含了一个身份认证器
    private AuthenticationManager authenticationManager;
    // 用于实现 rememberMe
    private RememberMeServices rememberMeServices = new NullRememberMeServices();
	private RequestMatcher requiresAuthenticationRequestMatcher;
    // 这两个 Handler 很关键, 分别别代表了认证成功和失败相应的处理器.
	private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
    // ...

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
        // ...
		Authentication authResult;
		try {
            // 此处实际上就是调用 UsernamePasswordAuthenticationFilter 的 attemptAuthentication 方法
			authResult = attemptAuthentication(request, response);
			if (authResult == null) {
				// 子类未完成认证, 立刻返回
				// return immediately as subclass has indicated that it hasn't completed authentication
				return;
			}
			// 保存 认证结果身份信息到 sessionStrategy
			sessionStrategy.onAuthentication(authResult, request, response);
		}
		// 在认证过程中可以直接抛出异常, 在过滤器中, 就像此处一样, 进行捕获
		catch (InternalAuthenticationServiceException failed) {
			// 内部服务异常
			unsuccessfulAuthentication(request, response, failed);
			return;
		}
		catch (AuthenticationException failed) {
			// Authentication failed 认证失败
			unsuccessfulAuthentication(request, response, failed);
			return;
		}
		// Authentication success 认证成功
		if (continueChainBeforeSuccessfulAuthentication) {
			chain.doFilter(request, response);
		}
		// 注意, 认证成功后过滤器把 authResult 结果也产地给了成功处理器.
		successfulAuthentication(request, response, chain, authResult);
	}
}
```

整个流程理解起来也并不难, 主要就是内部调用了 `authenticationManager` 完成认证, 根据认证结果执行 `successfulAuthentication` 或者 `unsuccessfulAuthentication`, 无论成功失败, 一般的实现都是转发或者重定向等处理, 不再细究 `AuthenticationSuccessHandler` 和 `AuthenticationFailureHandler`, 有兴趣的朋友, 可以去看看两者的实现类.


## 4.4 AnonymousAuthenticationFilter

匿名认证过滤器, 可能有人会想: 匿名了还有身份? 我自己对于 Anonymous 匿名身份的理解是 Spirng Security 为了整体逻辑的统一性, 即使是未通过认证的用户, 也给予了一个匿名身份. 而 `AnonymousAuthenticationFilter` 该过滤器的位置也是非常的科学的, 它位于常用的身份认证过滤器 (如 `UsernamePasswordAuthenticationFilter`, `BasicAuthenticationFilter`, `RememberMeAuthenticationFilter`) 之后, 意味着只有在上述身份过滤器执行完毕后, SecurityContext 依旧没有用户信息, `AnonymousAuthenticationFilter` 该过滤器才会有意义 -- 给与用户一个匿名身份.

### 源码分析

`org.springframework.security.web.authentication.AnonymousAuthenticationFilter.java`

```java

public class AnonymousAuthenticationFilter extends GenericFilterBean implements
		InitializingBean {

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private String key;
	private Object principal;
	private List<GrantedAuthority> authorities;

	// 自动创建一个 "anonymousUser" 的匿名用户, 其具有 ANONYMOUS 角色.
	public AnonymousAuthenticationFilter(String key) {
		this(key, "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	/**
	 * @param key key the key to identify tokens created by this filter. 用来识别该过滤器创建的身份
	 * @param principal the principal which will be used to represent anonymous users. 代表匿名用户的身份
	 * @param authorities the authority list for anonymous users 代表匿名用户的权限集合
	 */
	public AnonymousAuthenticationFilter(String key, Object principal,
			List<GrantedAuthority> authorities) {
		Assert.hasLength(key, "key cannot be null or empty");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
		this.key = key;
		this.principal = principal;
		this.authorities = authorities;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		// 过滤器链都执行到匿名认证过滤器这了还灭有身份信息, 塞一个匿名身份进去.
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			SecurityContextHolder.getContext().setAuthentication(
					createAuthentication((HttpServletRequest) req));
		}
		chain.doFilter(req, res);
	}

	protected Authentication createAuthentication(HttpServletRequest request) {
		// 创建一个 AnonymousAuthenticationToken
		AnonymousAuthenticationToken auth = new AnonymousAuthenticationToken(key,
				principal, authorities);
		auth.setDetails(authenticationDetailsSource.buildDetails(request));
		return auth;
	}
}
```

其实对比 `AnonymousAuthenticationFilter` 和 `UsernamePasswordAuthenticationFilter` 就可以发现一些门道了, `UsernamePasswordAuthenticationToken` 对应 `AnonymousAuthenticationToken`, 他们都是 `Authentication` 的实现类, 而 `Authentication` 则是被 `SecurityContextHolder(SecurityContext)` 持有的, 一切都被串联在了一起.

## 4.5 ExceptionTranslationFilter

`ExceptionTranslationFilter` 异常转换过滤器位于整个 `springSecurityFilterChain` 的后方, 用来转换整个链路中出现的异常, 将其转化，顾名思义，转化以意味本身并不处理. 一般其只处理两大类异常: `AccessDeniedException` 访问异常和 `AuthenticationException` 认证异常.

这个过滤器非常重要, 因为它将 Java 中的异常和 HTTP 的响应连接在了一起, 这样在处理异常时, 我们不用考虑密码错误该跳到什么页面, 账号锁定该如何, 只需要关注自己的业务逻辑, 抛出相应的异常便可. 如果该过滤器检测到 `AuthenticationException`, 则将会交给内部的 `AuthenticationEntryPoint` 去处理, 如果检测到 `AccessDeniedException`, 需要先判断当前用户是不是匿名用户, 如果是匿名访问, 则和前面一样运行 `AuthenticationEntryPoint`, 否则会委托给 `AccessDeniedHandler` 去处理, 而 `AccessDeniedHandler` 的默认实现, 是 `AccessDeniedHandlerImpl`. 所以 `ExceptionTranslationFilter` 内部的 `AuthenticationEntryPoint` 是至关重要的, 顾名思义: 认证的入口点.

### 源码分析

`org.springframework.security.web.access.ExceptionTranslationFilter.java`

```java 
public class ExceptionTranslationFilter extends GenericFilterBean {

	// ...
	private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
	private AuthenticationEntryPoint authenticationEntryPoint;
	private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
	private RequestCache requestCache = new HttpSessionRequestCache();

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		try {
			chain.doFilter(request, response);
		}
		catch (IOException ex) {
			throw ex;
		}
		catch (Exception ex) {
			// Try to extract a SpringSecurityException from the stacktrace
			Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
			RuntimeException ase = (AuthenticationException) throwableAnalyzer
					.getFirstThrowableOfType(AuthenticationException.class, causeChain);
			if (ase == null) {
				ase = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(
						AccessDeniedException.class, causeChain);
			}

			if (ase != null) {
				if (response.isCommitted()) {
					throw new ServletException("Unable to handle the Spring Security Exception because the response is already committed.", ex);
				}
				handleSpringSecurityException(request, response, chain, ase);
			}
			else {
				// Rethrow ServletExceptions and RuntimeExceptions as-is
				if (ex instanceof ServletException) {
					throw (ServletException) ex;
				}
				else if (ex instanceof RuntimeException) {
					throw (RuntimeException) ex;
				}
				// Wrap other Exceptions. This shouldn't actually happen
				// as we've already covered all the possibilities for doFilter
				throw new RuntimeException(ex);
			}
		}
	}

	// 处理异常转换的核心方法
	private void handleSpringSecurityException(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain, RuntimeException exception)
			throws IOException, ServletException {
		if (exception instanceof AuthenticationException) {
			// 重定向到登录端点
			sendStartAuthentication(request, response, chain, (AuthenticationException) exception);
		}
		else if (exception instanceof AccessDeniedException) {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authenticationTrustResolver.isAnonymous(authentication) || authenticationTrustResolver.isRememberMe(authentication)) {
				// 重定向到登录端点
				sendStartAuthentication(request, response, chain,
						new InsufficientAuthenticationException(
							messages.getMessage(
								"ExceptionTranslationFilter.insufficientAuthentication",
								"Full authentication is required to access this resource")));
			}
			else {
				// 交给 accessDeniedHandler 处理
				accessDeniedHandler.handle(request, response, (AccessDeniedException) exception);
			}
		}
	}
}
```

剩下的便是要搞懂 `AuthenticationEntryPoint` 和 `AccessDeniedHandler` 就可以了.

![authentication 时序图](https://gitee.com/chuanshen/development_notes/raw/master/Spring/spring-security-architecture/images/CP4-4-5_AuthenticationEntryPoint_inheritance.png?raw=true)

选择了几个常用的登录端点, 以其中第一个为例来介绍, 看名字就能猜到是认证失败之后, 让用户跳转到登录页面. 还记得我们一开始怎么配置表单登录页面的吗?

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()	// FormLoginConfigurer
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .permitAll();
    }
}
```

我们顺着 `formLogin` 返回的 `FormLoginConfigurer` 往下找，看看能发现什么，最终在 `FormLoginConfigurer` 的父类 `AbstractAuthenticationFilterConfigurer` 中有了不小的收获:

`org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer.java`
```java 
public abstract class AbstractAuthenticationFilterConfigurer<B extends HttpSecurityBuilder<B>, T extends AbstractAuthenticationFilterConfigurer<B, T, F>, F extends AbstractAuthenticationProcessingFilter>
		extends AbstractHttpConfigurer<T, B> {

	// ...
	// formLogin 不出所料配置了 AuthenticationEntryPoint
	private LoginUrlAuthenticationEntryPoint authenticationEntryPoint;

	// 认证失败的处理器
	private AuthenticationFailureHandler failureHandler;
	// ...
}
```

具体如何配置的就不看了, 我们得出了结论, `formLogin()` 配置了之后最起码做了两件事, 
1. 为 `UsernamePasswordAuthenticationFilter` 设置了相关的配置;
2. 配置了 `AuthenticationEntryPoint`;

登录端点还有 `Http401AuthenticationEntryPoint`, `Http403ForbiddenEntryPoint` 这些都是很简单的实现, 有时候我们访问受限页面, 又没有配置登录, 就看到了一个空荡荡的默认错误页面, 上面显示着 401, 403 就是这两个入口起了作用.

还剩下一个 `AccessDeniedHandler` 访问决策器未被讲解, 简单提一下: `AccessDeniedHandlerImpl` 这个默认实现类会根据 `errorPage` 和状态码来判断, 最终决定跳转的页面

`org.springframework.security.web.access.AccessDeniedHandlerImpl.java`
```java

public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
	// ...
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException,
			ServletException {
		if (!response.isCommitted()) {
			if (errorPage != null) {
				// Put exception into request scope (perhaps of use to a view)
				request.setAttribute(WebAttributes.ACCESS_DENIED_403,
						accessDeniedException);

				// Set the 403 status code.
				response.setStatus(HttpStatus.FORBIDDEN.value());

				// forward to error page.
				RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
				dispatcher.forward(request, response);
			}
			else {
				response.sendError(HttpStatus.FORBIDDEN.value(),
					HttpStatus.FORBIDDEN.getReasonPhrase());
			}
		}
	}
	// ...
}
```

## 4.6 FilterSecurityInterceptor

想想整个认证安全控制流程还缺了什么? 我们已经有了认证, 有了请求的封装, 有了 Session 的关联. 还缺一个: 由什么控制哪些资源是受限的, 这些受限的资源需要什么权限, 需要什么角色. 这一切和访问控制相关的操作, 都是由 `FilterSecurityInterceptor` 完成的.

`FilterSecurityInterceptor` 的工作流程可以理解如下: `FilterSecurityInterceptor` 从 `SecurityContextHolder` 中获取 `Authentication` 对象, 然后比对用户拥有的权限和资源所需的权限. 前者可以通过 `Authentication` 对象直接获得, 而后者则需要引入我们之前一直未提到过的两个类: `SecurityMetadataSource`, `AccessDecisionManager`. 理解清楚决策管理器的整个创建流程和 `SecurityMetadataSource` 的作用需要花很大一笔功夫, 这里, 暂时只介绍其大概的作用.

在 JavaConfig 的配置中, 我们通常如下配置路径的访问控制:

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
	http
		.authorizeRequests()
			.antMatchers("/resources/**", "/signup", "/about").permitAll()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
            .anyRequest().authenticated()
			.withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
				public <O extends FilterSecurityInterceptor> O postProcess(O fsi) {
					//fsi.setPublishAuthorizationSuccess(true);
					fsi.setAccessDecisionManager(customUrlDecisionManager);
                    fsi.setSecurityMetadataSource(customFilterInvocationSecurityMetadataSource);
					return fsi;
				}
			});
}
```

在 `ObjectPostProcessor` 的泛型中看到了 `FilterSecurityInterceptor`, 可以在其中配置 `SecurityMetadataSource`, `AccessDecisionManager` .

## 总结
本章在介绍过滤器时, 顺便进行了一些源码的分析, 目的是方便理解整个 Spring Security 的工作流. 伴随着整个过滤器链的介绍, 安全框架的轮廓应该已经浮出水面了, 下面的章节, 主要打算通过自定义一些需求, 再次分析其他组件的源码, 学习应该如何改造 Spring Security, 为我们所用.
---