package com.example.security.config;

import com.example.security.jwt.JwtAccessDeniedHandler;
import com.example.security.jwt.JwtAuthenticationEntryPoint;
import com.example.security.jwt.JwtSecurityConfig;
import com.example.security.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity // 기본적인 Web 보안을 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true) // PreAuthorize 어노테이션을 메서드 단위로 추가하기 위함
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // WebSecurityConfigurer 를 implements 하거나 WebSecurityConfigurerAdapter 를 extends 하여 추가적인 설정 진행

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(TokenProvider tokenProvider, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint, JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // h2-console 하위 모든 요청과 파비콘 관련 요청은 Spring Security 로직을 수행하지 않음
        web.ignoring().antMatchers("/h2-console/**", "/favicon.ico");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 토큰을 사용하기 때문에 csrf 설정 disable
                .csrf().disable()

                // Exception을 Handling할 때 jwtAuthenticationEntryPoint와 jwtAccessDeniedHandler룰 사용
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // H2 console을 위한 설정
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않으므로 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // 로그인 API, 회원가입 API는 토큰이 없는 상태에서 요청이 들어오므로 모두 permitAll 한다
                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated()

                // jwtFilter를 addFilterBefore로 등록한 JwtSecurityConfig클래스도 적용한다
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));


//        http
//                .authorizeRequests() // HttpServletRequest 를 사용하는 요청들에 대한 접근제한을 설정
//                .antMatchers("/api/hello").permitAll() // "/api/hello"에 대한 요청은 인증없이 접근을 허용하겠다
//                .anyRequest().authenticated(); // 나머지 요청들은 모두 인정되어야 한다
    }
}
