package com.example.user.config;

import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.SocialUserMapper;
import com.example.user.mapper.UserMapper;
import com.example.user.service.CustomUserDetailsService;
import com.example.user.service.KaKaoService;
import com.example.user.service.UserService;
import com.example.user.util.*;
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
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(request -> {
                    // CORS 설정을 커스터마이징하는 코드 시작.
                    CorsConfiguration corsConfiguration = new CorsConfiguration();// CORS 설정 객체 생성. 이 객체에 CORS 정책(허용 도메인, 메서드 등)을 설정
                    corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));  // 허용할 도메인(Origin)을 설정
                    corsConfiguration.setAllowedMethods(Collections.singletonList("*"));// 허용할 HTTP 메서드를 설정
                    corsConfiguration.setAllowCredentials(true);// 자격 증명(쿠키, 인증 헤더 등)을 요청에 포함하는 것을 허용
                    corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));// 클라이언트가 요청 시 보낼 수 있는 HTTP 헤더를 설정
                    corsConfiguration.setMaxAge(3600L);// CORS 설정의 캐시 지속 시간
                    corsConfiguration.setExposedHeaders(Arrays.asList("Set-Cookie", "Authorization"));
                    return corsConfiguration;
                }))
                .logout(logout -> logout.disable())
                .csrf(csrf -> csrf.disable())
                .formLogin(formLogin -> formLogin.disable())
                .httpBasic(httpBasic -> httpBasic.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/kakao-token", "/login").authenticated()
                        .anyRequest().permitAll());
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));//세션을 생성하거나 사용하지않음 jwt토큰 방식이기 때문에 세션 x



        // .class는 Spring Security에서 제공하는 필터로 커스텀한 필터를 앞에 붙이면 해당 필터보다 먼저 실행된다.
        // CustomRequestWrappingFilter 추가
        http.addFilterBefore(
                new CustomRequestWrappingFilter(), UsernamePasswordAuthenticationFilter.class);
        // JwtAuthenticationFilter 등록
        http.addFilterBefore(
                new JwtAuthenticationFilter(formJwtUtils,authenticationManager), UsernamePasswordAuthenticationFilter.class);

        // OAuth2LoginFilter 등록
        http.addFilterBefore(
                new OAuth2LoginFilter(kaKaoService, jwtUtils, userService),
                OAuth2LoginAuthenticationFilter.class);

        return http.build();
    }
}
