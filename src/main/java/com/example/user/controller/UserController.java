package com.example.user.controller;

import com.example.user.dto.*;
import com.example.user.mapper.UserMapper;
import com.example.user.service.KaKaoService;
import com.example.user.service.UserService;
import com.example.user.util.JwtUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;


import java.util.*;

@RestController
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class UserController {
    private final UserMapper userMapper;
    private final UserService userService;
    private final KaKaoService kaKaoService;
    private final JwtUtils jwtUtils; // JwtUtils를 주입받음

    // 사용자 ID로 UserDto 객체를 가져오는 메소드
    public UserDto findUserById(String userId) {
        return userMapper.findByUserId(userId);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader(value = "Authorization", required = false) String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", "유효하지 않은 Authorization 헤더입니다."));
        }

        // 토큰에서 Bearer 제거
        token = token.substring(7);

        try {
            // 토큰 기반 로그아웃 처리
            userService.logout(token);
            return ResponseEntity.ok(Map.of("message", "로그아웃이 성공적으로 완료되었습니다."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("message", "로그아웃 처리 중 오류가 발생했습니다."));
        }
    }


    //폼로그인
    @PostMapping("/formuser")
    public ResponseEntity<Map<String, String>> saveFormUser(@RequestBody FormInfoDto formInfoDto) {
        // 이미 로그인된 사용자 체크
        if (SecurityContextHolder.getContext().getAuthentication() != null &&
                SecurityContextHolder.getContext().getAuthentication().isAuthenticated() &&
                !(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message", "이미 로그인된 사용자입니다."));
        }


        FormUserDto formUserDto = formInfoDto.getFormUserDto();
        UserDto userDto = formInfoDto.getUserDto();

        // 사용자 정보 저장
        userService.saveFormUser(formUserDto, userDto);

        // Access Token과 Refresh Token 생성
        String accessToken = jwtUtils.createAccessToken(userDto.getUser_id());
        String refreshToken = jwtUtils.createRefreshToken(userDto.getUser_id());

        // 사용자 권한 추가
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        // 인증된 사용자 정보 설정
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDto.getUser_id(), null, authorities
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 응답 메시지 반환
        Map<String, String> response = new HashMap<>();
        response.put("message", "회원가입이 성공적으로 완료되었습니다.");
        response.put("userId", userDto.getUser_id());
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);
        return ResponseEntity.ok(response);
    }



    //비밀번호 찾기
    @PostMapping("find/password")
    public ResponseEntity<String> findPassword(@RequestBody findPasswordRequestDto findPasswordRequestDto) {
        try {
            userService.findPassword(
                    findPasswordRequestDto.getUserId(),
                    findPasswordRequestDto.getEmail(),
                    findPasswordRequestDto.getAuthCode(),
                    findPasswordRequestDto.getNewPassword()
            );
            return ResponseEntity.ok("비밀번호를 성공적으로 변경하였습니다.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    //로그인한 상태에서 비밀번호 변경
    @PostMapping("change/password")
    public ResponseEntity<String> changePassword(@RequestBody changePasswordRequestDto changePasswordRequestDto) {
        try {
            // 1. UserDto 조회
            UserDto userDto = userMapper.findByUserId(changePasswordRequestDto.getUserId());
            if (userDto == null) {
                return ResponseEntity.badRequest().body("사용자 정보를 찾을 수 없습니다.");
            }

            // 2. changePassword 메소드 호출
            userService.changePassword(
                    changePasswordRequestDto.getUserId(),
                    changePasswordRequestDto.getOldPassword(),
                    changePasswordRequestDto.getNewPassword()
            );

            return ResponseEntity.ok("비밀번호를 성공적으로 변경하였습니다.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }


    //소셜로그인
    @PostMapping("/api/kakao-token")
    public ResponseEntity<Map<String, String>> getAccessToken(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
            @RequestBody Map<String, String> tokenData,
            @RequestHeader(value = "Accept", defaultValue = "application/json") String acceptHeader,
            HttpServletRequest request // HttpServletRequest 추가
    ) {
        System.out.println("Authorization Header: " + authorizationHeader);

        // Authorization 헤더에서 Bearer Token 추출
        String accessToken;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7); // 'Bearer ' 이후의 토큰 값 추출
        } else {
            accessToken = null;
        }

        System.out.println("Access Token: " + accessToken);

        // 쿠키에서 refresh_token 추출
        String refreshTokenFromCookie = getRefreshTokenFromCookie(request);
        String refreshToken = tokenData.get("refresh_token");

        // 쿠키에 있는 refresh_token 우선 사용 (쿠키에 값이 있을 경우)
        if (refreshTokenFromCookie != null) {
            refreshToken = refreshTokenFromCookie;
        }

        System.out.println("리프레시 토큰: " + refreshToken);

        // 토큰 유효성 검사
        if (accessToken == null || accessToken.isEmpty()) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Access Token이 없습니다.");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        try {
            // 카카오 사용자 정보 조회
            kaKaoService.getKakaoUserInfo(accessToken, refreshToken);

            Map<String, String> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("refresh_token", refreshToken);
            System.out.println("응답 리프레시 토큰: " + refreshToken);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "카카오 사용자 정보 요청에 실패했습니다.");
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(500).body(errorResponse);
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