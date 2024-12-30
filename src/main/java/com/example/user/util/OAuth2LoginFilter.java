package com.example.user.util;

import com.example.user.dto.UserDto;
import com.example.user.service.KaKaoService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    public OAuth2LoginFilter(KaKaoService kaKaoService, JwtUtils jwtUtils) {
        this.kaKaoService = kaKaoService;
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization"); // 헤더에서 Authorization 값을 받아옴

        // Authorization 헤더에서 Bearer 토큰을 추출
        String accessToken = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7); // 'Bearer ' 이후의 토큰 값을 추출
        }

        // 토큰이 없으면 필터 체인을 진행하지 않음
        if (accessToken == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Access Token이 없습니다.");
            return;
        }

        // 카카오 서비스에서 사용자 정보를 가져오는 부분 (동기식 처리)
        try {
            var kaKaoDto = kaKaoService.getKakaoUserInfo(accessToken, null);

            if (kaKaoDto == null) {
                // 사용자 정보가 없으면 401 Unauthorized 처리
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("카카오 사용자 정보를 가져올 수 없습니다.");
                return;
            }

            // 카카오 사용자 정보를 통해 UserDto 생성
            UserDto user = kaKaoDto.getUserDto();

            // JWT 토큰 생성
            String jwtToken = jwtUtils.generateToken(user);
            System.out.println("jwt:" + jwtToken);

            // 응답에 JWT 토큰 추가 (응답이 커밋되지 않았을 때만 추가)
            if (!response.isCommitted()) {
                response.addHeader("Authorization", "Bearer " + jwtToken);
            }

            // OAuth2User 객체 생성
            OAuth2User oAuth2User = new DefaultOAuth2User(
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),  // 권한
                    Collections.singletonMap("user_id", user.getUser_id()),  // 사용자 정보 (user_id)
                    "user_id"  // 사용자의 이름 역할을 하는 키값
            );

            // OAuth2AuthenticationToken 생성
            OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                    oAuth2User,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                    "oauth2-client"  // OAuth2 로그인 클라이언트 이름
            );

            // SecurityContext에 인증된 사용자 정보 설정
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 필터 체인 진행
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            // 오류 발생 시 처리 (예: 사용자 정보 조회 실패 시)
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("카카오 사용자 정보 조회 실패: " + e.getMessage());
        }
    }
}
