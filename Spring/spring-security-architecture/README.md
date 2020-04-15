
这是一篇 Spring Security 体系结构的系列文章

源于 [徐靖峰 - Spring Security](https://www.cnkirito.moe/categories/Spring-Security/) 

---

<!-- TOC -->

- [Spring Security Architecture Overview](#spring-security-architecture-overview)
    - [1 核心组件](#1-核心组件)
        - [1.1 SecurityContextHolder](#11-securitycontextholder)
            - [获取当前用户的信息](#获取当前用户的信息)
        - [1.2 Authentication](#12-authentication)
            - [Spring Security 是如何完成身份认证的](#spring-security-是如何完成身份认证的)
        - [1.3 AuthenticationManager](#13-authenticationmanager)
        - [1.4 DaoAuthenticationProvider](#14-daoauthenticationprovider)

<!-- /TOC -->

---

# Spring Security Architecture Overview

较为简单或者体量较小的技术, 完全可以参考着 demo 直接上手, 但系统的学习一门技术则不然. 以我的认知, 一般的文档大致有两种风格: 
- Architecture First - 致力于让读者先了解整体的架构, 方便我们对自己的认知有一个宏观的把控;
- Code First - 以特定的 demo 配合讲解, 可以让读者在解决问题的过程中顺便掌握一门技术;

学习一个体系的技术, 我推荐 Architecture First, 正如本文标题所言, 这篇文章是我 Spring Security 系列的第一篇, 主要是根据 Spring Security 文档选择性 ~~ 翻译 ~~ 整理而成的一个架构概览, 配合自己的一些注释方便大家理解. 参考版本为 Spring Security 4.2.3.RELEASE.

## 1 核心组件

这一节主要介绍一些在 Spring Security 中常见且核心的 Java 类, 它们之间的依赖, 构建起了整个框架. 想要理解整个架构, 最起码得对这些类眼熟.

### 1.1 SecurityContextHolder

`SecurityContextHolder` 用于存储安全上下文 (security context) 的信息. 当前操作的用户是谁, 该用户是否已经被认证, 他拥有哪些角色权.... 这些都被保存在 `SecurityContextHolder` 中. `SecurityContextHolder` 默认使用 `ThreadLocal` 策略来存储认证信息. 看到 `ThreadLocal` 也就意味着, 这是一种与 **线程** 绑定的策略. Spring Security 在用户登录时自动绑定认证信息到当前线程, 在用户退出时, 自动清除当前线程的认证信息. 但这一切的前提, 是你在 web 场景下使用 Spring Security, 而如果是 Swing 界面, Spring 也提供了支持, `SecurityContextHolder` 的策略则需要被替换, 鉴于我的初衷是基于 web 来介绍 Spring Security, 所以这里以及后续, 非 web 的相关的内容都一笔带过.  

#### 获取当前用户的信息

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

### 1.2 Authentication

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

#### Spring Security 是如何完成身份认证的

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

### 1.3 AuthenticationManager

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

### 1.4 DaoAuthenticationProvider

`AuthenticationProvider` 最最最常用的一个实现便是 `DaoAuthenticationProvider`. 顾名思义, Dao 正是数据访问层的缩写, 也暗示了这个身份认证器的实现思路. 由于本文是一个 Overview, 姑且只给出其 UML 类图:

![DaoAuthenticationProvider UML](https://raw.githubusercontent.com/ChuanShenLive/development_notes/master/Spring/spring-security-architecture/images/CP1-1-4_DaoAuthenticationProvider_UML.png)

按照我们最直观的思路, 怎么去认证一个用户呢? 用户前台提交了用户名和密码, 而数据库中保存了用户名和密码, 认证便是负责比对同一个用户名, 提交的密码和保存的密码是否相同便是了. 

在 Spring Security 中, 提交的用户名和密码被封装成了 `UsernamePasswordAuthenticationToken`, 而根据用户名加载用户的任务则是交给了 `UserDetailsService`, 在 `DaoAuthenticationProvider` 中, 对应的方法便是 `retrieveUser`, 虽然有两个参数, 但是 `retrieveUser` 只有第一个参数起主要作用, 返回一个 `UserDetails`. 还需要完成 `UsernamePasswordAuthenticationToken` 和 `UserDetails` 密码的比对, 这便是交给 `additionalAuthenticationChecks` 方法完成的, 如果这个 `void` 方法没有抛异常, 则认为比对成功. 比对密码的过程, 用到了 `PasswordEncoder` 和 `SaltSource`, 密码加密和盐的概念相信不用我赘述了, 它们为保障安全而设计, 都是比较基础的概念.
---