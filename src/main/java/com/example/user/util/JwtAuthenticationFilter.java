package com.example.user.util;

import com.example.user.dto.UserDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
        private final formjwtutil formjwtutil;
        private final AuthenticationManager authenticationManager;

        private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

        // 로그인 요청을 처리하는 메서드
        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
                // 특정 경로에서만 필터 작동
                String requestURI = request.getRequestURI();
                if (!"/formuser".equals(requestURI)) {
                        log.info("Request URI '{}' is not /formuser. Skipping JwtAuthenticationFilter.", requestURI);
                        return null; // 다른 필터 체인으로 진행
                }

                String userId = request.getParameter("user_id");
                String password = request.getParameter("passwd");

                log.info("Attempting authentication for userId: {}", userId);

                if (userId == null || password == null) {
                        log.error("User ID or password is missing!");
                        throw new AuthenticationServiceException("User ID or password is missing");
                }

                // 로그인 인증을 위한 AuthenticationToken 생성
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userId, password);

                // AuthenticationManager를 통해 인증 시도
                return authenticationManager.authenticate(authenticationToken);
        }

        @Override
        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
                // 인증 성공 후 사용자 정보를 로그로 출력
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication != null) {
                        log.info("Authentication: {}", authentication.getPrincipal());
                } else {
                        log.error("Authentication is null");
                }

                // 특정 경로에서만 필터 작동
                String requestURI = request.getRequestURI();
                if (!"/formuser".equals(requestURI)) {
                        chain.doFilter(request, response); // 필터 체인 계속 진행
                        return;
                }

                String userId = ((UserDto) authResult.getPrincipal()).getUser_id();
                String accessToken = formjwtutil.createAccessToken(userId);
                String refreshToken = formjwtutil.createRefreshToken(userId);
                log.info("successfulAuthentication 호출됨");
                log.info("엑세스토큰: {}", accessToken);

                // 사용자 권한 추가
                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

                // 인증 객체 생성 후 SecurityContext에 설정
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        authResult.getPrincipal(), null, authorities); // authResult에서 Principal (userDto) 가져오기


                // 응답에 JWT 토큰 추가
                response.addHeader("Authorization", "Bearer " + accessToken);
                response.addHeader("Refresh-Token", refreshToken);

                // 필터 체인 계속 실행
                chain.doFilter(request, response);
        }

}
