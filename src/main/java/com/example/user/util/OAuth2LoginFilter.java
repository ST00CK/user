package com.example.user.util;

import com.example.user.dto.KaKaoDto;
import com.example.user.service.KaKaoService;
import com.example.user.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class OAuth2LoginFilter extends OncePerRequestFilter {
    private final KaKaoService kaKaoService;
    private final JwtUtils jwtUtils;
    private final UserService userService;

    public OAuth2LoginFilter(KaKaoService kaKaoService, JwtUtils jwtUtils, UserService userService) {
        this.kaKaoService = kaKaoService;
        this.jwtUtils = jwtUtils;
        this.userService = userService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 필터를 특정 경로 `/api/kakao-token`에만 작동하도록 설정
        String requestURI = request.getRequestURI();
        return !"/api/kakao-token".equals(requestURI);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");

        // Authorization 헤더에서 Bearer 토큰 추출
        String accessToken = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7); // 'Bearer ' 이후의 토큰 값을 추출
        }

        // refreshToken을 쿠키에서 추출
        String refreshToken = getRefreshTokenFromCookie(request);

        if (refreshToken == null) {
            refreshToken = request.getParameter("refresh_token"); // 쿠키에서 없을 경우, 쿼리 파라미터에서 가져옴
        }

        if (accessToken == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Access Token이 없습니다.");
            return;
        }

        try {
            // 카카오 사용자 정보 조회
            KaKaoDto kaKaoDto = kaKaoService.fetchKakaoUserInfo(accessToken, refreshToken);
            System.out.println("필터에서 가져온 refreshToken: " + refreshToken);

            if (kaKaoDto == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("카카오 사용자 정보를 가져올 수 없습니다.");
                return;
            }

            // 사용자 정보 저장 및 JWT 생성
            String result = userService.saveSocialUser(kaKaoDto.getSocialUserDto(), kaKaoDto.getUserDto());
            String jwtToken = jwtUtils.generateToken(kaKaoDto.getUserDto());
            response.addHeader("Authorization", "Bearer " + jwtToken);

            OAuth2User oAuth2User = new DefaultOAuth2User(
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                    Collections.singletonMap("userId", kaKaoDto.getUserDto().getUserId()),
                    "userId"
            );

            OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                    oAuth2User,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                    "oauth2-client"
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("카카오 사용자 정보 조회 실패: " + e.getMessage());
        }
    }

    // 쿠키에서 리프레시 토큰을 추출하는 메서드
    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null; // 리프레시 토큰이 없으면 null 반환
    }
}
