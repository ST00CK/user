package com.example.user.controller;

import com.example.user.dto.*;
import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.UserMapper;
import com.example.user.service.EmailService;
import com.example.user.service.KaKaoService;
import com.example.user.service.UserService;
import com.example.user.service.minio.MinioService;
import com.example.user.util.FormJwtUtils;
import com.example.user.util.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;


import java.util.*;

@RestController
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
@Tag(name = "User API", description = "사용자 관리 API")
public class UserController {
    private final UserMapper userMapper;
    private final UserService userService;
    private final KaKaoService kaKaoService;
    private final JwtUtils jwtUtils; // JwtUtils를 주입받음
    private final FormUserMapper formUserMapper;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final FormJwtUtils formJwtUtils;
    private final EmailService emailService;
    private final MinioService minioService;


    @GetMapping("/user/{userId}")
    public UserDto getUserInfo(@PathVariable String userId) {
        return userService.getUserInfo(userId);
    }


    @Operation(summary = "로그아웃", description = "사용자가 로그아웃합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그아웃 성공"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청")
    })
    //로그아웃
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(Map.of("message", "유효하지 않은 Authorization 헤더입니다."));
        }

        String token = authorizationHeader.substring(7); // Bearer 제거

        try {
            userService.logout(token);
            return ResponseEntity.ok(Map.of("message", "로그아웃이 성공적으로 완료되었습니다."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("message", "로그아웃 처리 중 오류가 발생했습니다."));
        }
    }


    @Operation(summary = "인증 이메일 발송", description = "회원가입 시 인증 이메일을 발송합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "인증 이메일이 전송되었습니다."),
            @ApiResponse(responseCode = "400", description = "이메일을 입력해주세요."),
            @ApiResponse(responseCode = "500", description = "이메일 전송에 실패했습니다.")
    })
    //회원가입 이메일 보내기
    @PostMapping("/send")
    public ResponseEntity<String> sendAuthEmail(@RequestBody Map<String, String> request, HttpSession session) {
        String email = request.get("email");

        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body("이메일을 입력해주세요.");
        }

        // 인증코드 생성
        String authCode = emailService.generateAuthCode();

        try {
            // 이메일 전송과 인증코드 세션 저장을 하나의 메서드에서 처리
            emailService.sendEmailAndSaveAuthCode(email, authCode, session);

            return ResponseEntity.ok("인증 이메일이 전송되었습니다.");
        } catch (MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("이메일 전송에 실패했습니다.");
        }
    }

    @Operation(summary = "인증 코드 검증", description = "회원가입 시 발송된 인증 코드를 검증합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "인증이 성공적으로 완료되었습니다."),
            @ApiResponse(responseCode = "400", description = "이메일과 인증 코드를 입력해주세요."),
            @ApiResponse(responseCode = "401", description = "인증 코드가 올바르지 않습니다."),
            @ApiResponse(responseCode = "500", description = "서버 오류")
    })
    //회원가입 이메일 검증
    @PostMapping("/verify")
    public ResponseEntity<String> verifyAuthCode(@RequestBody Map<String, String> request, HttpSession session) {
        String email = request.get("email");
        String inputCode = request.get("authCode");

        if (email == null || inputCode == null) {
            return ResponseEntity.badRequest().body("이메일과 인증 코드를 입력해주세요.");
        }

        // 세션에서 인증 코드 가져오기
        String storedAuthCode = (String) session.getAttribute("authCode");

        if (storedAuthCode == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("인증 코드가 저장되지 않았습니다.");
        }

        // 인증 코드 비교
        if (storedAuthCode.equals(inputCode)) {
            return ResponseEntity.ok("인증이 성공적으로 완료되었습니다.");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("인증 코드가 올바르지 않습니다.");
        }
    }


    @PostMapping("find/password")
    public ResponseEntity<String> sendPasswordFindEmail(@RequestBody Map<String, String> request, HttpSession session) {
        String email = request.get("email");

        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest().body("이메일을 입력해주세요.");
        }
        //인증코드 생성
        String authCode = emailService.generateAuthCode();

        try {
            emailService.sendPasswordFindEmail(email, authCode, session);
            //인증코드 세션 저장
            session.setAttribute("authCode", authCode);
            return ResponseEntity.ok("인증코드가 전송되었습니다.");
        } catch (MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("이메일 전송중 오류가 발생했습니다.");
        }

    }

    @Operation(summary = "폼 회원가입", description = "폼 데이터를 사용하여 사용자 정보를 저장합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "회원가입 성공"),
            @ApiResponse(responseCode = "403", description = "이미 로그인된 사용자")
    })
    // 폼 회원가입
    //폼 회원가입
    @PostMapping("/formuser")
    public ResponseEntity<Map<String, String>> saveFormUser(@RequestBody FormInfoDto formInfoDto, HttpServletResponse response) {
        // 이미 로그인된 사용자 체크
        if (SecurityContextHolder.getContext().getAuthentication() != null &&
                SecurityContextHolder.getContext().getAuthentication().isAuthenticated() &&
                !(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("message", "이미 로그인된 사용자입니다."));
        }
        // 클라이언트 요청에서 필요한 정보만 추출
        FormUserDto formUserDto = formInfoDto.getFormUserDto();
        UserDto userDto = formInfoDto.getUserDto();

        userDto.setFile("https://minio.bmops.org/stoock/Default.jpg");

        // 사용자 정보 저장
        userService.saveFormUser(formUserDto, userDto, true, response);

        // 응답 메시지 반환
        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("message", "회원가입이 성공적으로 완료되었습니다.");
        responseMap.put("userId", userDto.getUserId());

        return ResponseEntity.ok(responseMap);
    }


    @Operation(summary = "프로필 사진 변경", description = "유저의 프로필 변경")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "프로필 사진 변경 성공",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(example = "{\"message\": \"프로필 사진이 성공적으로 변경되었습니다.\", \"fileUrl\": \"https://minio.bmops.org/stoock/user123/new-image.jpg\"}"))),
            @ApiResponse(responseCode = "500", description = "서버 내부 오류",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(example = "{\"message\": \"프로필 사진 변경 중 오류가 발생하였습니다.\"}")))
    })
    @PostMapping("/upload")
    public ResponseEntity<Map<String, String>> photoChange(@RequestParam("userId") String userId, @RequestPart("file") MultipartFile file) {
        try {
            // 기존 사용자 정보 조회
            UserDto userDto = userMapper.findByUserId(userId);


            // 새로운 파일 업로드
            String fileName = minioService.uploadFile("stoock", userDto.getUserId(), file);

            // 파일 URL 생성
            String fileUrl = "https://minio.bmops.org/stoock/" + userDto.getUserId() + "/" + fileName;

            // 프로필 사진 URL 업데이트

            userMapper.updateProfileImage(userId, fileUrl); // 프로필 이미지 DB 업데이트
            userDto.setFile(fileUrl);

            // 응답 메시지 반환
            Map<String, String> responseMap = new HashMap<>();
            responseMap.put("message", "프로필 사진이 성공적으로 변경되었습니다.");
            responseMap.put("fileUrl", fileUrl);
            System.out.println("fileUrl" + fileUrl);
            System.out.println("file" + file);

            return ResponseEntity.ok(responseMap);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "프로필 사진 변경 중 오류가 발생하였습니다."));
        }
    }


    @Operation(summary = "폼 로그인", description = "사용자가 아이디와 비밀번호를 통해 로그인합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그인 성공"),
            @ApiResponse(responseCode = "401", description = "아이디 또는 비밀번호 오류")
    })
    //폼로그인
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginDto loginDto) {
        String userId = loginDto.getUserId();
        String passwd = loginDto.getPasswd();  // 로그인 요청에서 전달된 패스워드


        // 사용자 정보 조회
        LoginDto user = formUserMapper.findLoginUser(userId);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "사용자 정보가 일치하지 않습니다."));
        }

        // 암호화된 패스워드와 비교
        if (!bCryptPasswordEncoder.matches(passwd, user.getPasswd())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "비밀번호가 일치하지 않습니다."));
        }


        UserDto userInfo = userMapper.findByUserId(userId);

        // 응답 메시지 생성
        Map<String, String> responseMap = new HashMap<>();
        responseMap.put("message", "로그인이 성공적으로 완료되었습니다.");
        responseMap.put("userId", userInfo.getUserId());
        responseMap.put("email", userInfo.getEmail());
        responseMap.put("file", userInfo.getFile());
        responseMap.put("name", userInfo.getName());

        return ResponseEntity.ok(responseMap);
    }

    @Operation(summary = "폼 유저 액세스 토큰 갱신", description = "리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급받습니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "액세스 토큰 갱신 성공"),
            @ApiResponse(responseCode = "401", description = "유효하지 않은 리프레시 토큰")
    })
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshAccessToken(@CookieValue(value = "Refresh-Token", required = false) String refreshToken) {
        try {
            System.out.println("Received Refresh Token: " + refreshToken);

            // 리프레시 토큰을 검증하고 새로운 액세스 토큰을 발급
            String newAccessToken = formJwtUtils.refreshAccessToken(refreshToken);
            System.out.println("New Access Token: " + newAccessToken);

            // 🔹 서비스 계층을 통해 유저 정보 조회
            UserDto userDto = userService.findByRefreshToken(refreshToken);
            if (userDto == null) {
                System.out.println("DB에 해당 Refresh Token이 없음!");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "유효하지 않은 리프레시 토큰입니다."));
            }

            System.out.println("User Found: " + userDto.getUserId());

            // 액세스 토큰 갱신
            userDto.setAccessToken(newAccessToken);

            // 🔹 서비스 계층을 통해 액세스 토큰 업데이트
            userService.updateAccessToken(userDto.getUserId(), newAccessToken);

            // 새로운 액세스 토큰을 응답으로 반환
            return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", e.getMessage()));
        }
    }


    @Operation(summary = "사용자 ID로 폼로그인 사용자 정보 조회", description = "사용자 ID를 사용하여 사용자 정보를 가져옵니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "사용자 정보 조회 성공"),
            @ApiResponse(responseCode = "404", description = "사용자 정보가 없습니다.")
    })
    @GetMapping("/find")
    public ResponseEntity<FormUserDto> getUserById(@RequestParam String userId) {
        FormUserDto formUserDto = userService.getUserById(userId);

        if (formUserDto == null) {
            return ResponseEntity.status(404).body(null); // 사용자 미존재 시 404 반환
        }

        return ResponseEntity.ok(formUserDto); // 사용자 존재 시 200 OK 반환
    }


    @Operation(summary = "사용자 정보 조회", description = "사용자 ID를 통해 사용자 정보를 조회합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "사용자 정보 조회 성공"),
            @ApiResponse(responseCode = "404", description = "사용자가 존재하지 않음")
    })
    @GetMapping("/find/user")
    public ResponseEntity<UserDto> findByUserId(@RequestParam String userId) {
        UserDto userDto = userService.findByUserId(userId);

        if (userDto == null) {
            return ResponseEntity.status(404).body(null); // 사용자 미존재 시 404 반환
        }

        return ResponseEntity.ok(userDto); // 사용자 존재 시 200 OK 반환
    }


//    @Operation(summary = "비밀번호 찾기", description = "사용자가 ID, 이메일, 인증코드, 새 비밀번호를 사용해 비밀번호를 재설정합니다.")
//    @ApiResponses(value = {
//            @ApiResponse(responseCode = "200", description = "비밀번호 변경 성공"),
//            @ApiResponse(responseCode = "400", description = "잘못된 요청")
//    })
//    //비밀번호 찾기
//    @PostMapping("find/password")
//    public ResponseEntity<String> findPassword(@RequestBody findPasswordRequestDto findPasswordRequestDto) {
//
//        try {
//            userService.findPassword(
//                    findPasswordRequestDto.getUserId(),
//                    findPasswordRequestDto.getEmail(),
//                    findPasswordRequestDto.getAuthCode(),
//                    findPasswordRequestDto.getNewPassword()
//            );
//            return ResponseEntity.ok("비밀번호를 성공적으로 변경하였습니다.");
//        } catch (Exception e) {
//            return ResponseEntity.badRequest().body(e.getMessage());
//        }
//    }

    @Operation(summary = "비밀번호 변경", description = "로그인 상태에서 기존 비밀번호를 새 비밀번호로 변경합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "비밀번호 변경 성공"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청")
    })
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

    @Operation(summary = "카카오 로그인", description = "카카오 계정을 통해 로그인합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그인 성공"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청")
    })
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
            KaKaoDto kaKaoDto = kaKaoService.getKakaoUserInfo(accessToken, refreshToken);
            UserDto userdto = kaKaoDto.getUserDto();


            Map<String, String> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("refresh_token", refreshToken);
            response.put("userId", userdto.getUserId());
            response.put("name", userdto.getName());
            response.put("email", userdto.getEmail());
            response.put("file", userdto.getFile());
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