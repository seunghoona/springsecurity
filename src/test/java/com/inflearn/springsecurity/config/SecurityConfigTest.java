package com.inflearn.springsecurity.config;

import com.inflearn.springsecurity.SecurityController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.ResultMatcher;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@WebMvcTest(SecurityController.class)
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("사용자 로그인이 정상적으로 되는 확인")
    void formLoginSuccessTest() throws Exception {
        mockMvc.perform(formLogin()
                        .loginProcessingUrl("/login-proc")
                        .user("userId", "user")
                        .password("passwd", "1234"))
                .andExpect(authenticated())
                .andExpect(redirectedUrl("/"))
                .andExpect(status().is3xxRedirection())
        ;
    }

    @Test
    @DisplayName("사용자 로그인이 실패했는지 확인")
    void formLoginFail() throws Exception {
        mockMvc.perform(formLogin()
                        .loginProcessingUrl("/login-proc")
                        .user("userId", "user")
                        .password("passwd", "r4124"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login"))
                .andExpect(status().is3xxRedirection())
        ;
    }

    @Test
    @DisplayName("로그아웃 테스트")
    void logoutTest() throws Exception {
        mockMvc.perform(logout()
                        .logoutUrl("/logout")
                        )
                .andExpect(redirectedUrl("/login"))
        ;
    }

    @Test
    @DisplayName("리멤버 미 test")
    void rememberMeTest() throws Exception {
        MvcResult mvcResult = mockMvc.perform(formLogin()
                        .loginProcessingUrl("/login-proc")
                        .user("userId", "user")
                        .password("passwd", "1234")

                )
                .andReturn();
        Cookie remember = mvcResult.getResponse().getCookie("remember-me");

        this.mockMvc.perform(get("/")
                        .cookie(remember))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("로그인 실패시 리멤버 미 실패 ")
    void rememberMeNotWorkTest() throws Exception {
        MvcResult mvcResult = mockMvc.perform(formLogin()
                        .loginProcessingUrl("/login-proc")
                        .user("userId", "user")
                        .password("passwd", "1223234")

                )
                .andReturn();
        Cookie remember = mvcResult.getResponse().getCookie("remember-me");

        this.mockMvc.perform(get("/")
                        .cookie(remember))
                .andExpect(unauthenticated());
    }

}