package com.example.user.util;

import com.example.user.dto.UserDto;
import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.UserMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final FormUserMapper formUserMapper;
    private final JwtUtils jwtUtils; // JwtUtils 주입

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 사용자의 로그인 정보 추출
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String username = authResult.getName();

        // 사용자 정보 가져오기
        UserDto user = userMapper.findByUserId(username);

        // 사용자 활성 상태를 확인하는 로직 추가 (예: email로 활성화 여부를 판단)
        if (user == null || user.getEmail() == null || user.getEmail().isEmpty()) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "사용자 계정이 비활성화되었습니다.");
            return;
        }

        // JwtUtils를 사용하여 엑세스 토큰과 리프레시 토큰 생성
        String accessToken = jwtUtils.createAccessToken(username);
        String refreshToken = jwtUtils.createRefreshToken(username);

        // 토큰을 DB에 업데이트
        userMapper.updateAccessTokenAndRefreshToken(username, accessToken, refreshToken);

        // 토큰을 응답 헤더에 추가
        response.addHeader("Authorization", "Bearer " + accessToken);
        response.addHeader("Refresh-Token", refreshToken);
    }

    // 로그아웃 시 호출되는 메서드 추가
    public void handleLogout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 로그아웃 시 SecurityContext에서 인증 정보 제거
        SecurityContextHolder.clearContext();

        // JWT 토큰을 응답에서 삭제 (옵션)
        response.setHeader("Authorization", null); // JWT 토큰을 삭제

        // 로그아웃 성공 응답
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("Logout successful");

    }
}
