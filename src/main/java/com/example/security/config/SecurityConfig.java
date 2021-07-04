package com.example.security.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity // 기본적인 Web 보안을 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // WebSecurityConfigurer 를 implements 하거나 WebSecurityConfigurerAdapter 를 extends 하여 추가적인 설정 진행

    @Override
    public void configure(WebSecurity web) throws Exception {
        // h2-console 하위 모든 요청과 파비콘 관련 요청은 Spring Security 로직을 수행하지 않음
        web.ignoring().antMatchers("/h2-console/**", "/favicon.ico");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests() // HttpServletRequest 를 사용하는 요청들에 대한 접근제한을 설정
                .antMatchers("/api/hello").permitAll() // "/api/hello"에 대한 요청은 인증없이 접근을 허용하겠다
                .anyRequest().authenticated(); // 나머지 요청들은 모두 인정되어야 한다
    }
}
