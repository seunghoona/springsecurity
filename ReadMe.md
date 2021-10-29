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
