package com.example.user.config;

import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.UserMapper;
import com.example.user.service.CustomUserDetailsService;
import com.example.user.service.UserService;
import com.example.user.util.JwtAuthenticationFilter;
import com.example.user.util.JwtUtils;
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
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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
    private final ClientRegistrationRepository clientRegistrationRepository; // 소셜 로그인 설정을 위한 ClientRegistrationRepository

    // AuthenticationManager 빈 등록
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // CORS 설정을 위한 CorsConfigurationSource 빈 등록
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("http://localhost:3000"); // 클라이언트 도메인
        corsConfiguration.addAllowedMethod("OPTIONS"); // OPTIONS 요청을 허용
        corsConfiguration.addAllowedMethod("GET"); // GET 요청을 허용
        corsConfiguration.addAllowedMethod("POST"); // POST 요청을 허용
        corsConfiguration.addAllowedMethod("PUT"); // PUT 요청을 허용
        corsConfiguration.addAllowedMethod("DELETE"); // DELETE 요청을 허용
        corsConfiguration.addAllowedHeader("*"); // 모든 헤더를 허용
        corsConfiguration.addAllowedHeader("Authorization"); // Authorization 헤더 허용
        corsConfiguration.setAllowCredentials(true); // 자격 증명 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration); // 모든 경로에 CORS 설정 적용

        return source;
    }
    // SecurityFilterChain 정의
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager(), userMapper, formUserMapper, jwtUtils);

        return http.csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // CORS 활성화
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(auth -> auth
                        .requestMatchers("/formuser", "/api/kakao-token", "/socialuser").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginProcessingUrl("/formuser")
                        .successHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                            response.getWriter().write("Login successful");
                        })
                        .permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/socialuser")
                        .successHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                            response.getWriter().write("Social login successful");
                        })
                        .permitAll())
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID", "access_token")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            jwtAuthenticationFilter.handleLogout(request, response);
                            response.setStatus(HttpServletResponse.SC_OK);
                            response.getWriter().write("Logout successful");
                        })
                        .permitAll())  // 로그아웃 후 리디렉션을 방지
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
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
}
