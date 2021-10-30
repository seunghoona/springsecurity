##  스프링 시큐리의 의존성 추가시 무엇이 일어나는가?
+ WAS 실행시 스프링 시큐리티의 초기화 작업 및 보안 설정이 진행된다.
+ 별도의 설정이 구현을 하지 않아도 기본적인 웹 보안 기능이 현재 시스템에 연동되어 작동한다
  + 모든 요청은 인증이 되어야 접근
  + 인증 방식은 form방식과 httpBasic 로그인 방식을 제공한다.
  + 기본 로그인 페이지 제공
  + 기본계종 한개를 제공
    + user / console에 출력
    + 

## 아키텍처 
 
+ WebSecurityConfigurerAdapter.java
  + 스프링 시큐리티의 웹 보안 기능 초기화 및 설정을 담당한다.


+ SecurityConfig.java
  + 사용자 정의 보안 설정 클래스 
  

+ HttpSecurity.java
  + 세부적인 보안 기능을 설정하는 API 제공 
  + 인증API, 인가 API를 가지고 있따.


## Form 인증 
1. client get/home을 요청 
2. 인증이 안되면 로그인페이지로 리다이렉트 
3. client post/login
4. session 및 인증 토큰 생성 및 저장 
5. client에서 요청시 서버에 저장된 세션 정보를 가지고서 접근 

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
            .formLogin()
            .loginPage("사용자 정의 페이지")
            .defaultSuccessUrl("로그인 성공후 이동 페이지")
            .failureUrl("로그인 실패 후 이동 페이지")
            .usernameParameter("아이디 파라미터명 설정")
            .passwordParameter("패스워드 파라미터명 설정")
            .loginProcessingUrl("로그인 Form Action Url")
            .successHandler("로그인 성공 후 핸들러")
            .failureHandler("로그인 실패 후 핸들러");
  }
}
```

### 이를통해 알게된점
오류정의    
junit test시 아래와 같은 오류가 발생한 이유는 url path앞단에 '/' 를 붙여야 한다
SecurityConfig에서도 **loginProcessingUrl** 도 '/'를 반드시 붙여만 정상적으로 테스트가 가능하다.

>'url' should start with a path or be a complete HTTP URL: login-proc
>

## UserNamePasswordAuthenticationFilter에 대해 알아보자

### Login Form 인증  Flow
1. UserNamePasswordAuthenticationFilter가 최초로 유저의 요청정보를 가지고 매칭되는지 요청
```java
public abstract class AbstractAuthenticationProcessingFilter {
    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // AntPathRequestMatcher login으로 요청인지 확인
        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }
        try {
            //UsernamePasswordAuthenticationToken을 통해 Authentication 정보를 Provider에게 위임
            Authentication authenticationResult = attemptAuthentication(request, response);
            if (authenticationResult == null) {
                // return immediately as subclass has indicated that it hasn't completed
                return;
            }
            this.sessionStrategy.onAuthentication(authenticationResult, request, response);
            // Authentication success
            if (this.continueChainBeforeSuccessfulAuthentication) {
                chain.doFilter(request, response);
            }
            successfulAuthentication(request, response, chain, authenticationResult);
        }
        catch (InternalAuthenticationServiceException failed) {
            this.logger.error("An internal error occurred while trying to authenticate the user.", failed);
            unsuccessfulAuthentication(request, response, failed);
        }
        catch (AuthenticationException ex) {
            // Authentication failed
            unsuccessfulAuthentication(request, response, ex);
        }
    }
}
```
2. AntPathRequestMatcher("/login") login과 매칭되는지 확인
   + 매칭이 안 된 경우 
     + chain.doFilter(다음필터를 실행)
   + 매칭이 된 경우  
3. Authentication (username,password)를 가지고서 인증요청
4. AuthenticationManager는 AuthenticationProvider에게 위임
5. AuthenticationProvider에서 인증처리
   + 인증실패 
     + AuthenticationException 발생
   + 인증성공
6. Authentication(User + Authorities) 에 대해 저장 요청
7. SecurityContext에 저장 
8. SuccessHandler();

## 2.로그아웃 처리 LogoutFilter

```java

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .logout()
                .logoutUrl("로그아웃 처리 url")
                .logoutSuccessUrl("/login")
                .deleteCookies("로그아웃 후 쿠키 삭제")
                .addLogoutHandler("로그아웃핸들러")
                .logoutSuccessHandler("로그아웃 성공후 핸들러")
        ;
    }
}
```
### Logout flow
1. 사용자가 logout 요청
2. AntPathRequestMatcher(/logout)
    + 매칭이 안 된 경우
        + chain.doFilter(다음필터를 실행)
    + 매칭이 된경우 
3. Authentication 가 인증된 객체정보를 securityContext에서 가져온다.
4. SecurityContextLogoutHandler
    + 세션무효화
    + 쿠키삭제
    + SecurityContextHolder.clearContext()를 호출해서 저장된정도 삭제한다.
5. SimpleUrlLogoutSuccessHandler로 로그인페이지로 이동

### LogoutFilter 기본 Handler
1. CookieCleaningLogoutHandler // 쿠키삭제
2. CsrfLogoutHandler
3. SecurityContextLogoutHandler // 세션삭제
4. LogoutSuccessEventPublishingLogoutHandler
    + 우리가 만든 핸들러를 호출한다.

## 3. Remember ME 인증 및 RememberMeAuthenticationFilter
> 세션이 만료되고 웹 브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능    
> Remember-me 쿠키에 대한 http요청을 확인한 후 토큰 기반 인증을 사용해 유효성을 검사하고 토큰이 검증되면 사용자는 로그인된다.

### 설정방법 

```java

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .rememberMe()
                .rememberMeParameter("기본파라미터 명은 remember-me")
                .tokenValiditySeconds("기본 값은 14일")
                .alwaysRemember("리멤버미 기능이 활성화되지 않아도 항상실행")
                .userDetailsService("userDetailsService")
        ;
    }
}
```

### Remember-me flow
1. 사용자의 요청을 하지만 세션이 만료된 상태에서 요청을 합니다.
   + 사용자는 remember-me를 통해 로그인을 시도했습니다.
2. RememberMeAuthenticationFilter
   1. 아래와 같은 경우 작동하게 됩니다.
      1. Authentication null 
         + 사용자의 세션이 만료
         + SecurityContext  Authentication 없는경우
         + Null이 아닌경우는 해당 정보가 존재하는 것으로 판단하여 작동하지 않습니다.
      2. form 인증 rememer-me 쿠키를 발급 받아서 전송하는 경우
3. RememberMeService
   1. TokenBeasedRememberMeService
      + 14일 만료기간 
   2. PersistentTokenBasedRememberMeService
      + db에 저장 
4. Token Cookie 를 추출 
5. Token 존재한다면 
   + 존재하지 않는다면 
     + chain.doFilter(다음필터를 실행)
6. DecodeToken(정상유무 판단) 규칙체크 
   1. 조건에 부합하지 않는다면 Exception 발생
      1. Token 이 서로 일치하는가? 
      2. User 계정이 존재하는가? 
      3. 새로운 Authentication 생성 
      4. AuthenticationManager 인증처리
      
## 4.익명사용자 AnonymousAuthenticationFilter

> 익명사용자 인증 필터   
> 익명사용자와 인증사용자를 구분해서 처리하기 위한 용도로 사용   
> 화면에서 인증여부를 구현할 때 isAnonymous()와 isAuthenticated()로 구분해서 사용    
> 인증 객체를 세션에 저장하지 않는다.

1. 사용자가 요청을 보냄 
2. AnonymousAuthenticationFilter
   + Authentication 가 존재하지 않는다면 (인증하지 않은 사용자)
     + AnonymousAuthenticationToken을 생성
   + 인증한 사용자라면 
     + chain.doFilter(다음필터를 실행)
3. SecurityContextHolder에 익명객체를 저장처리

### 정리

1. 인증이 되기 전이나, 이후 의 사용자 모두 유효한 인증토큰을 갖고있지 못하면 `익명 사용자`이다

2. `익명 사용자`는 로그인이 가능한 경로를 통해 인증허가를 을 받게 될 경우, 일반 사용자로 등극하여, 로그인 접속 및 향후 접속유지가 가능하게된다.

3. 인증을 받지 못한 사용자는 `익명 사용자`로 분류되어, `익명 사용자` 인증 토큰이(인증 객체) 익명 사용자 관리 명목으로 생성되지만, 로그인과 관련된 접근 권한은 없다(세션 생성이 되지않음) -> `redirect /login page`

4. `익명 사용자` 전용으로 발급된 인증토큰을 통해, 향후 `익명 사용자` 접근 여부를 관리 할 수 있다


## 5. 동시세션 제어 
1. 최대 허용 개수(1개)를 사용자가 초과한경우 
   + 이전 사용자 세션만료 
     + 사용자1 로그인 -> 사용자 세션생성 
     + 사용자2 로그인 -> 세션 생성 사용자1세션 만료 
     + 사용자1은 세션 만료로 인하여 조회 불가능 
   + 현재 사용자 인증 실패 
     + 사용자1 로그인 -> 사용자1 세션생성 
     + 사용자2 로그인 -> 사용자1이 가지고 있기 때문에 사용자2는 예외발생

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                .maximumSessions("최대 허용 가능 세션수 , -1인경우 무제한 로그인세션허용")
                .maxSessionsPreventsLogin("동시로그인 차단, false : 기존세션 만료, true : 예외던짐")
                .expiredUrl("세션이 만료된 경우 이동할 페이지")
        ;
    }
}
```

### 5.세션 고정보호
1. 공격자가 서버로 공격을 시도합니다.
2. 공격자에 의한 세션정보를 사용자에게 쿠키를 심어 놓습니다.
3. 사용자는 공격자가 가진 세션 쿠키를 가지고 로그인을 시도하면 인증에 성공하게되며 
4. 사용자의 세션정보를 공격자도 동일하게 공유하게 됩니다.

#### 위와 같은 공격을 방어를 해야합니다. 
어떻게 방어를 해야할까요 ? 
1. 사용자가 인증을 할 때마다 새로운 세션이 생성되도록 처리하면됩니다.
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                .sessionFixation().changeSessionId(); // 기본값 {
        // none,
        // changeSessionId servlet 3.1 이상 이전 세션값 사용
        // migrateSession, servlet 3.1 이하 이전 세션값 사용
        // newSession 이전의 세션값을 사용하지 못함
        // }
        ;
    }
}

```

### 5. 세션정책
+ SessionCreationPolicy.IF_REQUIRED (기본값)
+ 스프링시큐리티가 항상세션생성
  + SessionCreationPolicy.Always
+ 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
  + SessionCreationPolicy.Never
+ 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
  + SessionCreationPolicy.Stateless
    + + jwt에서 사용
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        ;
    }
}

```


### SessionManagementFilter
1. 세션관리
   + 인증시 사용자의 세션정보를 등록 조회 삭제 등의 세션 이력을관리
2. 동시적 세션제어 
   + 동일 계정으로 접속이 허용되는 최대 세션 수를 제한
3. 세션고정보호
   + 인증할 때마다 세션쿠키를 새로발급하여 공격자의 쿠키조작을방지
4. 세션생성정책
   + Always, IF_Required,Never,Stateless

###  ConcurrentSessionFilter

+ 매 요청마다 현재 사용자의 세션 만료 여부 체크
+ 세션이 만료되었을 경우 즉시 만료처리 
+ session.isExpired () == true
  + 로그아웃
  + 즉시 오류페이지 응답

### flow
1. `사용자1` 로그인 요청 
2. `UsernamePasswordAuthenticationFilter`가 `ConcurrentSessionControlAuthenticationStrategy`를 호출합니다.
   + ConcurrentSessionControlAuthenticationStrategy
     + 동시성 세션을 처리하는 클래스 
     + 인증을 시도하는 `사용자1`의 session 수가 몇 개인지 확인을 한다.
   + ChangeSessionIdAuthenticationStrategy
     + 세션고정보호를 처리하는 클래스 
     + `사용자1`이 인증시도할 때는 새로운 session와 쿠키를 발급합니다.
   + RegisterSessionAuthenticationStrategy
     + 사용자의 세션의 정보를 저장하는 클래스 
     + 사용자 세션정보의 수가 1로 증가하게 된다.
3. `사용자2` 로그인 요청
   + ConcurrentSessionControlAuthenticationStrategy
     + sessionCount == maxSession 수가 같은경우
       + 인증실패 전략인 경우
         + SessionAuthenticationException
       + 세션 만료 전략인 경우
         + session.expireNow();
         + ChangeSessionIdAuthenticationStrategy 클래스
           + session.changeSessionId();
         + RegisterSessionAuthenticationStrategy 클래스 
           + 세션정보등록
4. `사용자1`이 다시 요청하는경우 
   + ConcurrentSessionsFilter는 매요청마다 확인 
     + session.isExpired 로 확인 `ConcurrentSessionControlAuthenticationStrategy`에게 확인
   + logout & 메시지 전송


## 6. 권한 설정 및 표현식
설정시 구체적인 경로가 먼저오고 그것보다 큰 범위의 경로가 뒤에 오도록해야한다. 

1. antMatchers 
   + 경로설정 
2. hasRole 
   + 해당 권한을 가졌는가? 
3. access
   + 조금 더 구체적인 표현식을 통해 처리할 수있다.
   ```java
    http.antMatchers("/**").access("hasRole('ADMIN') or hasRole('SYS')")
    ```

|메소드|동작|
|:---:|:---:|
|hasRole()|사용자가 주어진 `역할`이 있다면 접근을 허용|
|hasAuthority()| 사용자가 주어진 `권한`이 있따면 접근허용|
|hasAnyRole()| 사용자가 주어진 `역할`이 있다면|
|hasAnyAuthority| 사용자가 주언진 `권한`중 어떤 것이라도 있다면 접근|
|hasIpAddress | 주어진 IP로부터 요청이 왔다면 접근을 허용 |


### 인메모리 사용자 생성 방법 

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER")
                .and()
                .withUser("sys").password("{noop}1234").roles("SYS")
                .and()
                .withUser("admin").password("{noop}1234").roles("ADMIN");
    }
}
```

## 7. ExceptionTranslationFilter 

### AuthenticationException
 + 인증 예외처리 
   + 로그인 페이지 이동, 401 오류코드 전달
 + 인증 예외가 발생하기 전의 요청정보를 저장 
   + RequestCache 사용자의 이전 요청 정보를 세션에 저장하고 이를 꺼내 오는 매커니즘 
     + SavedRequest 사용자가 요청했던 request 파라미터 값들 , 그 당시의 헤더 값들 등이 저장 
### AccessDeniedException
 + 인가 예외 처리 
   + AccessDeniedHandler 에서 예외 처리하도록 제공 


### flow
1. 사용자가 `request(/user)`를 요청
2. FilterSecurityInterceptor 
   + 인증 된 사용자가 아닌 경우 `AuthenticationException` 을 발생 
      + `AuthenticationEntryPoint` 에서 로그인 페이지로 이동 
      + 사용자의 요청관 정보를 저장 
        + `HttpSessionRequestCache` 에서 관리 
        + Session에 담긴 DefaultSavedRequest 객체 정보 `HttpSessionRequestCache`가 관리한다.
   + 인증은 되었지만 인가 정보가 다른 경우 
     + `AccessDeniedException` 발생 
       + AccessDeniedHandler 클래스를 호출해서 `response.redirect("인가 처리페이지")`로 보낸다.

### 설정방법 

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .exceptionHandling()
                .authenticationEntryPoint("인증 실패시 처리")
                .accessDeniedHandler("인가 실패시 처리")
        
                .formlogin()
                .successHandler((request, response, authentication) -> {
                    // 세션에 담겨진 요청했던 주소로 이동 시킴
                    RequestCache requestCache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                    response.sendRedirect(savedRequest.getRedirectUrl());
                })
        ;
    }
}
```

## 8.RequestCacheAwareFilter
+ 미리 저장된 캐싱된 데이터를 담고 활용할 수 있도록 하는 필터 
1. 사용자가 인증 없이 요청하는경우 `NULL`인 상태
2. 이후 `ExceptionTranslateFilter`에서 예외처리를 담당하면서 이전에 유저가 요청한 정보 `HttpSessionRequestCache` 에서 관리하게 된다.
3. 이후 사용자가 다시 요청을 시도하는 경우 `RequestCacheAwareFilter`는 더 이상 NULL이 아니며 이전에 요청한 사용자의 정보를 가지고서 다음 필터에게
4. 해당 정보를 넘겨주게된다.
### 설정정보 
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .formlogin()
                .successHandler((request, response, authentication) -> {
                    // 세션에 담겨진 요청했던 주소로 이동 시킴
                    RequestCache requestCache = new HttpSessionRequestCache();
                    // 사용자가 인증 받기전에 요청했던 정보를 가지고있는 객체 
                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                    response.sendRedirect(savedRequest.getRedirectUrl());
                })
        ;
    }
}
```

## CSRF, CsrfFilter
1. `사용자`가 쇼핑몰로 로그인함으로써 쿠키를 받습니다. `http://shop.naver.com`
2. `공격자`가 사용자에게 링크를 이용자에게 전달하게 됩니다. `http://shop.naver.com/adress=공격자집주소`
3. `사용자`는 링크를 클릭함으로써 사용자의 승인이나 인지 없이 배송지가 등록된다.
4. 위 문제를 해결하기 위해서 `CsrfFilter` 이용할 수 있다.

## CsrfFilter 무엇인가
+ 모든 요청에 래덤하게 생성된 토큰을 HTTP 파라미터로 요구 
+ 요청시 전달되는 토큰값과 서버에 저장된 실제 값과 비교한 후 만약 일치하지 않으면 요청은 실패한다.
  + HTTP  메소드 `PATCH,POST,PUT,DELETE`로 요청하는 경우 `토큰`값과 `토큰파라미터이름`을 가지고서 요청해야합니다.


# 스프링 시큐리티 주요 아키텍처

## 1. DelegatingProxyChain

1. Servlet Filter 스프링의 Bean을 사용할 수 없다. 
2. `DelegatingFilterProxy`를 이용하여 `Servlet Filter` 에서 `Spring Bean` 사용이 가능하게 한다.
   + `springSecurityFilterChain` 이름으로 생성된 빈을 `ApplicationContext` 에서 찾아 요청을 위임할 수 있게된다.

## FilterChainProxy
+ 지금 까지 나열된 Filter 관리 
+ `DelegatingFilterProxy`으로 부터 요청을 위임받는 `FilterChainProxy` 실제 보안 처리 
+ `springSecurityFilterChain`의 이름으로 생성되는 필터 빈 
+ 스프링 시큐리티 초기화 시 생성되는 필터들을 관리하고 제어 
  + 스프링 시큐리티가 기본적으로 생성하는 필터 
  + 설정 클래스에서 API 추가 시 생성되는 필터 
+ 사용자의 요청을 필터 순서대로 호출하여 전달 
+ 사용자 정의 필터를 생성해서 기존의 필터 전,후로 추가 가능 
  + 필터의 순서 정의 
+ 마지막 필터까지 인증 및 인가 예외가 발생하지 않으면 보안 통과

## flow 
1. 사용자가 요청
2. `Servlet Container` 에서 `DelegatinFilterProxy` 필터가 `SpringContainer`의 `SpringSecurityFilterChain` 에게 위임을 요청하게 된다.
```xml
<filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>

<filter-mapping>
  <filter-name>springSecurityFilterChain</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```
3. `springSecurityFilterChain` 이 가지고 있는 bean `FilterChainProxy` 이다.

## 과정을 확인해보자
1. Sprin 시작
2. `SecurityFilterAutoConfiguration` 에서 `DelegatingFilterProxy` bean을 등록한다.
```java
public class SecurityFilterAutoConfiguration {
    @Bean
    @ConditionalOnBean(name = DEFAULT_FILTER_NAME)
    public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration(
            SecurityProperties securityProperties) {
        // bean 등록
        DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean(
                DEFAULT_FILTER_NAME);
        registration.setOrder(securityProperties.getFilter().getOrder());
        registration.setDispatcherTypes(getDispatcherTypes(securityProperties));
        return registration;
    }
}
```
3. `WebSecurityConfiguration`에서 `DEFAULT_FILTER_NAME`으로 bean 을생성하는데 실제 bean은 `WebSeuciry.performBuild()`에서 FilterChainProxy 빈을 생성한다.

4. 실제 사용자가 요청 
5. `DelegatingFilterProxy` 에서 webApplicationContext를 통해 해당되 `DEFAULT_FILTER_NAME`의 빈을 찾아서 해당 bean 담겨진 무수한 filter들을 처리하게 된다.

## 2. 필터 초기화와 다중 설정 클래스

+ 설정클래스 별로 보안 기능이 각각 작동 
+ 설정 클래스 별로 RequestMatcher 설정 
  ```java
    http.antMatcher("/admin/**")
    ```
+ 설정 클래스 별로 필터가 생성 
+ 각각의 설정들은 `Filter` 정보,`RequestMacher` 정보를 가지는 `SecurityFilterChain` 클래스를 생성하게 됩니다.
+ 여러개의 `SecurityFilterChain`은  `FilterChainProxy`가 `SecurityFilterChains`으로 각각의 chain 정보를 가지게 됩니다.

![2-2-1.png](src/main/resources/img/2-2-1.png)

![img.png](src/main/resources/img/2-2-2.png)

```java
public class FilterChainProxy {
    private List<Filter> getFilters(HttpServletRequest request) {
            int count = 0;
            for (SecurityFilterChain chain : this.filterChains) {
                if (logger.isTraceEnabled()) {
                    logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)", chain, ++count,
                            this.filterChains.size()));
                }
                // 각각의 필터정보들증 matches와 동일한 설정정보를 가진 필터 정보를 가져와서 필터를 처리하게 됩니다.
                if (chain.matches(request)) {
                    return chain.getFilters();
                }
            }
            return null;
        }
}
``` 

## 오류
+ 두개를 설정하는 경우 순서를 달리해야한다는 exception 발생    
  + @Order on WebSecurityConfigurers must be unique. Order of 100 was already
+ 설정시에 anyRequest로 전체 범위를 먼저 설정하는 경우 

## 설정방법
+ 위 설정 방법은 `.antMatcher("/admin/**")` 특정 URL 을 기준으로 설정을 처리했으며 
+ 아래 설정은은 모든 인증 방식에 대해서 permitAll처리했다.
+ **다중설정을 할 경우에는 더 넓은 범위의 패턴을 뒤로 둬야한다.**   
그 이유는 설정의 순서에 따라 탐색을 하게 되는데 더 넓은 범위를 먼저 체크하게 된다면 더 좁은 범위의 설정 부분을 체크하지 못하고 인증 없이 다른 사용자가 접근이 가능하게 되는 것이다. 
```java
@Configuration
@EnableWebSecurity
@Order(0)
public class AdminSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/admin/**")
                .authroizeRequest()
                .anyRequest().authenticated()
                .and()
                .formLogin();
        ;
    }
}

@Configuration
@Order(1)
public class DefaultSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authroizeRequest()
                .anyRequest().permitAll()
                .and()
                .formLogin();
    }
}
```