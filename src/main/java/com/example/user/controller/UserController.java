package com.example.user.controller;

import com.example.user.dto.*;
import com.example.user.mapper.UserMapper;
import com.example.user.service.KaKaoService;
import com.example.user.service.UserService;
import com.example.user.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
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
//        if (SecurityContextHolder.getContext().getAuthentication() != null) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "이미 로그인된 사용자입니다."));
//        }

        FormUserDto formUserDto = formInfoDto.getFormUserDto();
        UserDto userDto = formInfoDto.getUserDto();

        userService.saveFormUser(formUserDto, userDto);

        // Access Token과 Refresh Token 생성
        String accessToken = jwtUtils.createAccessToken(userDto.getUser_id());
        String refreshToken = jwtUtils.createRefreshToken(userDto.getUser_id());

        // SecurityContext에 인증된 사용자 정보 설정
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER")); // 권한 추가


        // SecurityContext에 인증된 사용자 정보 설정
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDto.getUser_id(), null, authorities
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        System.out.println("폼유저떠라" + authentication);
        // 응답 메세지 생성
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


    @PostMapping("/api/kakao-token")
    public ResponseEntity<Map<String, String>> getAccessToken(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
            @RequestBody Map<String, String> tokenData,
            @RequestHeader(value = "Accept", defaultValue = "application/json") String acceptHeader
    ) {
        System.out.println("Authorization Header: " + authorizationHeader);
        System.out.println("Token Data: " + tokenData);

        // Authorization 헤더에서 Bearer Token 추출
        String accessToken;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7); // 'Bearer ' 이후의 토큰 값 추출
        } else {
            accessToken = null;
        }

        System.out.println("Access Token: " + accessToken);

        String refreshToken = tokenData.get("refresh_token");

        // 토큰 유효성 검사
        if (accessToken == null || accessToken.isEmpty()) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Access Token이 없습니다.");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        try {
            KaKaoDto kaKaoDto = kaKaoService.getKakaoUserInfo(accessToken, refreshToken);

            Map<String, String> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("refresh_token", refreshToken);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "카카오 사용자 정보 요청에 실패했습니다.");
            errorResponse.put("error", e.getMessage());
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    // 소셜 로그인
    @PostMapping("/socialuser")
    public ResponseEntity<Map<String, Object>> saveSocialUser(@RequestBody Map<String, Object> requestData) {
        // 전달받은 socialUserDto와 userDto 추출
        Map<String, Object> socialUserDtoMap = (Map<String, Object>) requestData.get("socialUserDto");
        Map<String, Object> userDtoMap = (Map<String, Object>) requestData.get("userDto");
        System.out.println("떠라아아" + requestData);

        SocialUserDto socialUserDto = new SocialUserDto();
        socialUserDto.setUser_id((String) socialUserDtoMap.get("user_id"));
        socialUserDto.setProvider_type((String) socialUserDtoMap.get("provider_type"));

        UserDto userDto = new UserDto();
        userDto.setUser_id((String) userDtoMap.get("user_id"));
        userDto.setName((String) userDtoMap.get("name"));
        userDto.setEmail((String) userDtoMap.get("email"));
        userDto.setAccess_token((String) userDtoMap.get("access_token"));
        userDto.setRefresh_token((String) userDtoMap.get("refresh_token"));
        userDto.setFile((String) userDtoMap.get("file"));



        // 데이터베이스에서 사용자가 존재하는지 확인하고, 저장된 정보로 토큰 검증
        UserDto existingUser = userService.findByUserId(userDto.getUser_id());

        if (existingUser != null) {
            // 데이터베이스에 사용자 정보가 존재하면, 저장된 토큰과 비교하여 검증
            if (existingUser.getAccess_token().equals(userDto.getAccess_token())) {
                // 유효한 토큰인 경우, 사용자 정보 저장
                userService.saveSocialUser(socialUserDto, userDto);

                Map<String, Object> response = new HashMap<>();
                response.put("socialUserDto_user_id", socialUserDto.getUser_id());
                response.put("socialUserDto_provider_type", socialUserDto.getProvider_type());
                response.put("userDto_user_id", userDto.getUser_id());
                response.put("userDto_name", userDto.getName());
                response.put("userDto_email", userDto.getEmail());
                response.put("userDto_file", userDto.getFile());
                response.put("userDto_access_token", userDto.getAccess_token());
                response.put("userDto_refresh_token", userDto.getRefresh_token());

                // OAuth2User 생성
                OAuth2User oAuth2User = new DefaultOAuth2User(
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                        Collections.singletonMap("user_id", userDto.getUser_id()),
                        "user_id"
                );

                OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                        oAuth2User, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")), "oauth2-client"
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
                System.out.println("사용자1" + authentication);

                response.put("message", "소셜 로그인 회원가입 성공");
                return ResponseEntity.ok(response);
            } else {
                // 유효하지 않은 토큰인 경우, 리프레시 토큰으로 새 액세스 토큰 발급
                KaKaoService.TokenResponse tokenResponse = kaKaoService.refreshTokens(userDto.getRefresh_token());
                userDto.setAccess_token(tokenResponse.getAccessToken());
                userDto.setRefresh_token(tokenResponse.getRefreshToken());

                // 새 토큰과 사용자 정보로 저장
                userService.saveSocialUser(socialUserDto, userDto);

                Map<String, Object> response = new HashMap<>();
                response.put("socialUserDto_user_id", socialUserDto.getUser_id());
                response.put("socialUserDto_provider_type", socialUserDto.getProvider_type());
                response.put("userDto_user_id", userDto.getUser_id());
                response.put("userDto_name", userDto.getName());
                response.put("userDto_email", userDto.getEmail());
                response.put("userDto_file", userDto.getFile());
                response.put("userDto_access_token", userDto.getAccess_token());
                response.put("userDto_refresh_token", userDto.getRefresh_token());

                // OAuth2User 생성
                OAuth2User oAuth2User = new DefaultOAuth2User(
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                        Collections.singletonMap("user_id", userDto.getUser_id()),
                        "user_id"
                );

                OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                        oAuth2User, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")), "oauth2-client"
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
                System.out.println("사용자2" + authentication);

                response.put("message", "소셜 로그인 회원가입 성공");
                return ResponseEntity.ok(response);
            }
        } else {
            // 사용자가 없다면 새로 저장
            userService.saveSocialUser(socialUserDto, userDto);

            Map<String, Object> response = new HashMap<>();
            response.put("socialUserDto_user_id", socialUserDto.getUser_id());
            response.put("socialUserDto_provider_type", socialUserDto.getProvider_type());
            response.put("userDto_user_id", userDto.getUser_id());
            response.put("userDto_name", userDto.getName());
            response.put("userDto_email", userDto.getEmail());
            response.put("userDto_file", userDto.getFile());
            response.put("userDto_access_token", userDto.getAccess_token());
            response.put("userDto_refresh_token", userDto.getRefresh_token());

            // OAuth2User 생성
            OAuth2User oAuth2User = new DefaultOAuth2User(
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                    Collections.singletonMap("user_id", userDto.getUser_id()),
                    "user_id"
            );

            OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                    oAuth2User, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")), "oauth2-client"
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            System.out.println("사용자3" + authentication);

            response.put("message", "소셜 로그인 회원가입 성공");
            return ResponseEntity.ok(response);
        }
    }


}

