package com.example.user.config;

import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.SocialUserMapper;
import com.example.user.mapper.UserMapper;
import com.example.user.service.CustomUserDetailsService;
import com.example.user.service.KaKaoService;
import com.example.user.service.OAuth2UserService;
import com.example.user.service.UserService;
import com.example.user.util.JwtAuthenticationFilter;
import com.example.user.util.JwtUtils;
import com.example.user.util.OAuth2LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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
    private final AuthenticationConfiguration authenticationConfiguration;
    private final SocialUserMapper socialUserMapper;
    private final KaKaoService kaKaoService;

    // AuthenticationManager 빈 등록
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // AuthenticationProvider 빈 등록
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(bCryptPasswordEncoder);
        return authProvider;
    }

    // UserDetailsService 빈 등록
    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService(userMapper, formUserMapper);
    }

//    @Bean
//    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
//        return new JwtAuthenticationFilter(authenticationManager(), userMapper, jwtUtils);
//    }

    @Bean
    public OAuth2LoginFilter oauth2LoginFilter() throws Exception {
        return new OAuth2LoginFilter( kaKaoService, jwtUtils); // OAuth2UserService, KaKaoService, JwtUtils를 사용하여 OAuth2LoginFilter 생성
    }

    @Bean
    public OAuth2UserService oAuth2UserService() {
        return new OAuth2UserService(socialUserMapper, jwtUtils, userMapper); // 필요한 의존성으로 OAuth2UserService 생성
    }




    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration corsConfiguration = new CorsConfiguration();

                        corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                        corsConfiguration.setAllowCredentials(true);
                        corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
                        corsConfiguration.setMaxAge(3600L);
                        corsConfiguration.setExposedHeaders(Arrays.asList("Set-Cookie", "Authorization"));

                        return corsConfiguration;
                    }
                }));
        // csrf 비활성화
        http.csrf(csrf -> csrf.disable());
        // 폼로그인 비활성화
        http.formLogin(formLogin -> formLogin.disable());
        http.httpBasic(httpBasic -> httpBasic.disable());

        // 경로별 인가 작업
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/kakao-token").authenticated()
                .anyRequest().permitAll());

        // OAuth2LoginFilter 필터 추가
        http.addFilterAfter(new OAuth2LoginFilter(kaKaoService,jwtUtils), UsernamePasswordAuthenticationFilter.class);
//        // JWT 필터 추가
//        http.addFilterAfter(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);


        // 세션 설정
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
