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
    private final FormJwtUtill formjwtutil;
    private final AuthenticationConfiguration authenticationConfiguration;
//    private final AuthenticationManager authenticationManager;




    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(bCryptPasswordEncoder);
        return authProvider;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService(userMapper, formUserMapper);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(request -> {
                    CorsConfiguration corsConfiguration = new CorsConfiguration();
                    corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                    corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                    corsConfiguration.setAllowCredentials(true);
                    corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
                    corsConfiguration.setMaxAge(3600L);
                    corsConfiguration.setExposedHeaders(Arrays.asList("Set-Cookie", "Authorization"));
                    return corsConfiguration;
                }))
                .logout(logout -> logout.disable())
                .csrf(csrf -> csrf.disable())
                .formLogin(formLogin -> formLogin.disable())
                .httpBasic(httpBasic -> httpBasic.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/kakao-token", "/login").authenticated()
                        .anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));



        // CustomRequestWrappingFilter 추가
        http.addFilterBefore(
                new CustomRequestWrappingFilter(), UsernamePasswordAuthenticationFilter.class);
        // JwtAuthenticationFilter 등록
        http.addFilterBefore(
                new JwtAuthenticationFilter(formjwtutil,authenticationManager), UsernamePasswordAuthenticationFilter.class);

        // OAuth2LoginFilter 등록
        http.addFilterBefore(
                new OAuth2LoginFilter(kaKaoService, jwtUtils, userService),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
