package com.example.user.util;

import com.example.user.dto.LoginDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
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
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final FormJwtUtill formjwtutil;  // 클래스명 수정
    private final AuthenticationManager authenticationManager;

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);



    // 로그인 요청을 처리하는 메서드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        try {
            // CustomHttpServletRequestWrapper 사용
            CustomHttpServletRequestWrapper wrappedRequest = new CustomHttpServletRequestWrapper(request);
            String requestBody = wrappedRequest.getBody(); // 요청 본문 캐싱된 값 읽기

            // JSON 파싱 후 인증 처리
            LoginDto loginDto = new ObjectMapper().readValue(requestBody, LoginDto.class);
            String userId = loginDto.getUserId();
            String passwd = loginDto.getPasswd();

            if (userId == null || passwd == null) {
                throw new AuthenticationServiceException("User ID or password is missing");
            }
            log.info("AuthenticationManager: {}", authenticationManager);
            // 인증 토큰 생성 및 반환
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(userId, passwd);

            return authenticationManager.authenticate(authenticationToken);
        } catch (IOException e) {
            throw new AuthenticationServiceException("Unable to read request body", e);
        }
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        try {

            SecurityContextHolder.getContext().setAuthentication(authResult);
            // 인증 후 인증 정보를 SecurityContext에 설정
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null) {
                log.info("Authentication: {}", authentication.getPrincipal());
            } else {
                log.error("Authentication is null");
            }

            String username = ((User) authResult.getPrincipal()).getUsername();
            log.info("Generating JWT tokens for user: {}", username);

            String accessToken = formjwtutil.createAccessToken(username);
            String refreshToken = formjwtutil.createRefreshToken(username);

            // 사용자 권한 추가
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

            // 인증 객체 생성 후 SecurityContext에 설정
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    authResult.getPrincipal(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            log.debug("Authentication token with authorities set in SecurityContext");

            // JWT 토큰을 응답 헤더에 추가
            response.addHeader("Authorization", "Bearer " + accessToken);
            log.debug("JWT tokens added to response headers.");

            // 리프레시 토큰을 HttpOnly 쿠키에 추가
            Cookie refreshCookie = new Cookie("Refresh-Token", refreshToken);
            refreshCookie.setHttpOnly(true);  // JavaScript에서 접근 불가
            refreshCookie.setSecure(true);    // HTTPS에서만 전송
            refreshCookie.setPath("/");      // 쿠키 유효 경로 설정
            refreshCookie.setMaxAge(60 * 60 * 24 * 7); // 쿠키 만료 기간 설정 (7일)
            response.addCookie(refreshCookie);

            log.debug("JWT refresh token added to response cookie.");


            // 필터 체인 진행 전에 예외를 처리하고 종료
            try {
                // 필터 체인 계속 진행
                CustomHttpServletRequestWrapper wrappedRequest = new CustomHttpServletRequestWrapper(request);
                chain.doFilter(wrappedRequest, response); // wrappedRequest 사용
                log.debug("Filter chain continued with wrapped request.");
            } catch (Exception e) {
                log.error("Error during filter chain execution: {}", e.getMessage(), e);
                throw e;
            }
        } catch (Exception e) {
            log.error("Error during successful authentication: {}", e.getMessage(), e);
            throw e;
        }
    }
}
