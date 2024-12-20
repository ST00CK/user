package com.example.user.controller;

import com.example.user.dto.*;
import com.example.user.mapper.UserMapper;
import com.example.user.service.KaKaoService;
import com.example.user.service.UserService;
import com.example.user.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

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
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String token) {
        System.out.println("로그아웃 요청 받음");
        if (token == null || !token.startsWith("Bearer ")) {
            // Authorization 헤더가 없거나 형식이 잘못되었을 때
            System.out.println("Authorization 헤더가 없습니다.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", "Authorization 헤더가 없습니다."));
        }

        // "Bearer " 제거
        token = token.substring(7);
        System.out.println("추출된 토큰: " + token);

        // 서비스에 로그아웃 요청
        userService.logout(token);

        // 로그아웃 성공 메시지 반환
        Map<String, String> response = new HashMap<>();
        response.put("message", "로그아웃이 성공적으로 완료되었습니다.");
        return ResponseEntity.ok(response);
    }

    //폼로그인
    @PostMapping("/formuser")
    public ResponseEntity<Map<String, String>> saveFormUser(@RequestBody FormInfoDto formInfoDto) {
        FormUserDto formUserDto = formInfoDto.getFormUserDto();
        UserDto userDto = formInfoDto.getUserDto();

        userService.saveFormUser(formUserDto, userDto);

        // Access Token과 Refresh Token 생성
        String accessToken = jwtUtils.createAccessToken(userDto.getUser_id()); // 인스턴스 메서드 호출
        String refreshToken = jwtUtils.createRefreshToken(userDto.getUser_id());

        // 응답 메세지 생성
        Map<String, String> response = new HashMap<>();
        response.put("message", "회원가입이 성공적으로 완료되었습니다.");
        response.put("userId", userDto.getUser_id());
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);  // 토큰도 함께 반환

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


    // 카카오 토큰을 받아오는 API - 'access_token'을 직접 받음
    @PostMapping("/api/kakao-token")

    public Mono<ResponseEntity<Map<String, String>>> getAccessToken(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader, // Authorization 헤더에서 access_token 읽음
            @RequestBody Map<String, String> tokenData // Body에서는 refresh_token만 받음
    ) {

        // Authorization 헤더에서 Bearer Token 추출
        String accessToken;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7); // 'Bearer ' 이후의 토큰 값 추출
        } else {
            accessToken = null;
        }

        String refreshToken = tokenData.get("refresh_token"); // Body에서 refresh_token 추출

        // 토큰 유효성 검사
        if (accessToken == null || accessToken.isEmpty()) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Access Token이 없습니다.");
            return Mono.just(ResponseEntity.badRequest().body(errorResponse));
        }

        // Access Token을 사용하여 사용자 정보를 받아오는 서비스 호출
        return kaKaoService.getKakaoUserInfo(accessToken, refreshToken)
                .flatMap(kaKaoDto -> {
                    Map<String, String> response = new HashMap<>();
                    response.put("access_token", accessToken);
                    response.put("refresh_token", refreshToken);
                    return Mono.just(ResponseEntity.ok(response));
                })
                .onErrorResume(e -> {
                    if (refreshToken != null && !refreshToken.isEmpty()) {
                        return kaKaoService.refreshAccessToken(refreshToken)
                                .flatMap(tokenResponse -> {
                                    String newAccessToken = tokenResponse.getAccessToken();
                                    Map<String, String> response = new HashMap<>();
                                    response.put("access_token", newAccessToken);
                                    response.put("refresh_token", refreshToken);
                                    return Mono.just(ResponseEntity.ok(response));
                                });
                    } else {
                        Map<String, String> errorResponse = new HashMap<>();
                        errorResponse.put("message", "카카오 사용자 정보 요청에 실패했습니다.");
                        errorResponse.put("error", e.getMessage());
                        return Mono.just(ResponseEntity.status(500).body(errorResponse));
                    }
                });
    }
    // 소셜 로그인
    @PostMapping("/socialuser")
    public Mono<ResponseEntity<Map<String, Object>>> saveSocialUser(@RequestBody Map<String, Object> requestData) {
        // 전달받은 socialUserDto와 userDto 추출
        Map<String, Object> socialUserDtoMap = (Map<String, Object>) requestData.get("socialUserDto");
        Map<String, Object> userDtoMap = (Map<String, Object>) requestData.get("userDto");

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

        // 클라이언트에서 받은 Access Token으로 카카오 사용자 정보를 가져오는 방식
        return kaKaoService.getKakaoUserInfo(userDto.getAccess_token(), userDto.getRefresh_token())
                .flatMap(kaKaoDto -> {
                    // 사용자 정보 저장
                    return userService.saveSocialUser(socialUserDto, userDto)
                            .map(result -> {
                                // 응답 데이터 준비
                                Map<String, Object> response = new HashMap<>();
                                response.put("socialUserDto_user_id", socialUserDto.getUser_id());
                                response.put("socialUserDto_provider_type", socialUserDto.getProvider_type());

                                response.put("userDto_user_id", userDto.getUser_id());
                                response.put("userDto_name", userDto.getName());
                                response.put("userDto_email", userDto.getEmail());
                                response.put("userDto_file", userDto.getFile());
                                response.put("userDto_access_token", userDto.getAccess_token());
                                response.put("userDto_refresh_token", userDto.getRefresh_token());

                                // 성공 메시지
                                response.put("message", "소셜 로그인 회원가입이 성공적으로 완료되었습니다.");
                                response.put("result", result);

                                return ResponseEntity.ok(response);
                            });
                })
                .onErrorResume(e -> {
                    // 오류 처리
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("message", "소셜 로그인 회원가입에 실패했습니다.");
                    errorResponse.put("error", e.getMessage());
                    return Mono.just(ResponseEntity.status(500).body(errorResponse));
                });
    }
}
