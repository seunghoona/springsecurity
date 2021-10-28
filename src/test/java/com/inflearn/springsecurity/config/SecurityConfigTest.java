package com.inflearn.springsecurity.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@WebMvcTest
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

}