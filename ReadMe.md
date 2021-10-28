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
      
   
   
