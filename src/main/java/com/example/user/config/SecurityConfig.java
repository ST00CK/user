package com.example.user.config;

import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.SocialUserMapper;
import com.example.user.mapper.UserMapper;
import com.example.user.service.CustomUserDetailsService;
import com.example.user.service.KaKaoService;
import com.example.user.service.UserService;
import com.example.user.service.minio.MinioService;
import com.example.user.util.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@MapperScan("com.example.user.mapper")
public class SecurityConfig {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserMapper userMapper;
    private final FormUserMapper formUserMapper;
    private final JwtUtils jwtUtils;
    private final UserService userService;
    private final SocialUserMapper socialUserMapper;
    private final KaKaoService kaKaoService;
    private final FormJwtUtils formJwtUtils;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final MinioService minioService;





    //인증 관리자, 필터에서 요청을 받으면 AuthenticationProvider를 찾아서 인증
    //필터로부터 인증처리를 지시받으면 가지고 있는 인증 처리자들 중에서 현재 인증처리를 할 수있는 Provider에게 인증처리를 위임하여 인증처리 수행후 인증 성공을 한다면 반환
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }



    //실질적으로 인증 절차가 이뤄지는 곳
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(); //사용자 정보 인증처리
        authProvider.setUserDetailsService(userDetailsService()); // 사용자 정보를 로드할 서비스
        authProvider.setPasswordEncoder(bCryptPasswordEncoder); // 비밀번호 암호화
        return authProvider;
    }

    //UserDetailsService로부터 DB에 저장된 사용자 정보와 비교 후 넘어온 절보를 가지고 Authentication 객체를 생성하거나 인증되지 못한경우에는 예외 처리를 해주는 역할을 한다.
    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService(userMapper, formUserMapper);
    }

    //Spring Security5.x버전부터 기존 xml 또는 체이닝 메서드 방식보다 람다 표현식을 활용한 구성방식이 도입
    //가독성,간결성,유지보수성을 크게 향상 시키기 위해 도입됨
    //기존 체이닝 방식으로 사용하면 코드가 길어지지만 람다식을 활용하면 메서드 체인 내부의 구조가 단순화되고 읽기 쉬워진다.
    // (parameter) <- {function body}
    // parameter = auth
    // fucntion body = 입력값을 사용해 수행할 작업
    // SPRING SECURITY 설정의 핵심 요청 및 인증/인가 규칙을 정의
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(request -> {
                    CorsConfiguration corsConfiguration = new CorsConfiguration();
                    corsConfiguration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "https://front.bmops.org")); // 여러 도메인 허용
                    corsConfiguration.setAllowedMethods(Collections.singletonList("*")); // 모든 HTTP 메서드 허용
                    corsConfiguration.setAllowCredentials(true); // 자격 증명 허용
                    corsConfiguration.setAllowedHeaders(Collections.singletonList("*")); // 모든 헤더 허용
                    corsConfiguration.setMaxAge(3600L); // 캐시 지속 시간 설정
                    corsConfiguration.setExposedHeaders(Arrays.asList("Set-Cookie", "Authorization")); // 노출할 헤더 설정
                    return corsConfiguration;
                }))
                .logout(logout -> logout.disable())
                .csrf(csrf -> csrf.disable())
                .formLogin(formLogin -> formLogin.disable())
                .httpBasic(httpBasic -> httpBasic.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/kakao-token", "/login").authenticated()
                        .anyRequest().permitAll());

        // 세션 쿠키 설정
        http
                .addFilterBefore(new SessionCookieFilter(), UsernamePasswordAuthenticationFilter.class);


        // CustomRequestWrappingFilter 및 JwtAuthenticationFilter 설정
        http.addFilterBefore(new CustomRequestWrappingFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new JwtAuthenticationFilter(formJwtUtils, authenticationManager), UsernamePasswordAuthenticationFilter.class);

        // OAuth2LoginFilter 등록
        http.addFilterBefore(new OAuth2LoginFilter(kaKaoService, jwtUtils, userService), OAuth2LoginAuthenticationFilter.class);

        return http.build();
    }
}
