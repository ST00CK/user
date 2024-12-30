package com.example.user.util;

import com.example.user.dto.UserDto;
import com.example.user.mapper.UserMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final JwtUtils jwtUtils;
    private final RestTemplate restTemplate = new RestTemplate();
    private final String TOKEN_VALIDATION_URL = "https://api.example.com/v1/user/access_token_info"; // API URL

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String token = null;

        try {
            // 헤더에서 JWT 토큰 추출
            token = request.getHeader("Authorization");
            System.out.println("Authorization Header: " + token); // JWT 토큰 출력
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7); // "Bearer "를 제거한 토큰 값
            } else {
                // 예외 처리 없이 null 반환
                System.out.println("No Bearer Token Found");
                return null;
            }

            // 1. JWT 토큰을 검증하고 인증 객체 생성
            if (jwtUtils.validateToken(token)) {
                System.out.println("Valid Token: " + token);
                String username = jwtUtils.getUsernameFromToken(token);
                System.out.println("Username: " + username);

                UserDto user = userMapper.findByUserId(username);
                if (user == null || user.getEmail() == null || user.getEmail().isEmpty()) {
                    System.out.println("User is disabled or missing email");
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "사용자 계정이 비활성화되었습니다.");
                    return null;
                }

                // 역할을 GrantedAuthority 리스트로 변환
                List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                System.out.println("Authorities: " + authorities);

                // ROLE_USER 권한 추가
                authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

                // 인증 객체 생성 (인증된 사용자 설정)
                Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                return authentication;
            } else {
                System.out.println("Invalid Token");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "잘못된 JWT 토큰입니다.");
                return null;
            }
        } catch (IOException e) {
            e.printStackTrace();
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "토큰 처리 중 오류가 발생했습니다.");
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "서버 오류가 발생했습니다.");
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
            return null;
        }
    }

    private boolean validateAccessTokenWithApi(String token) {
        try {
            System.out.println("Validating token with external API");
            // API 호출 시 Authorization 헤더 포함
            ResponseEntity<String> response = restTemplate.getForEntity(
                    TOKEN_VALIDATION_URL,
                    String.class
            );

            // 상태 코드가 200이면 유효한 토큰
            boolean isValid = response.getStatusCode() == HttpStatus.OK;
            System.out.println("Token validation response: " + isValid);
            return isValid;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error during token validation API call");
            return false; // API 호출 실패 시 유효하지 않다고 판단
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        try {
            System.out.println("Authentication successful, proceeding with filter chain");
            // 인증이 성공하면 체인 진행
            chain.doFilter(request, response);
        } catch (IOException | ServletException e) {
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "인증 성공 후 필터 처리 중 오류가 발생했습니다.");
        }
    }

    // 로그아웃 시 호출되는 메서드
    public void handleLogout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            System.out.println("Handling logout, clearing context");
            SecurityContextHolder.clearContext();
            response.setHeader("Authorization", null); // JWT 토큰을 삭제
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("Logout successful");
        } catch (IOException e) {
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "로그아웃 처리 중 오류가 발생했습니다.");
        }
    }
}
