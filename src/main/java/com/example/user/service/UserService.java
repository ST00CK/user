package com.example.user.service;

import com.example.user.client.UserClient;
import com.example.user.dto.FormUserDto;
import com.example.user.dto.SocialUserDto;
import com.example.user.dto.UserDto;
import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.SocialUserMapper;
import com.example.user.mapper.UserMapper;
import com.example.user.util.JwtUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper; // 생성자 주입
    private final FormUserMapper formUserMapper; // 생성자 주입
    private final BCryptPasswordEncoder bCryptPasswordEncoder; // 생성자 주입
    private final SocialUserMapper socialUserMapper;
    private final JwtUtils jwtUtils;
    private final UserClient userClient;


    //open feign 유저정보 보내기
    public UserDto getUserInfo(String userId) {
        return userClient.getUserInfo(userId);
    }

    //폼유저 찾기
    public FormUserDto getUserById(String userId) {
        return formUserMapper.findById(userId);
    }

    //유저테이블에서 유저 찾기
    public UserDto findByUserId(String userId) {
        return userMapper.findByUserId(userId);
    }


    //엑세스토큰 업데이트
    @Transactional
    public void updateAccessToken(String userId, String accessToken) {
        userMapper.updateAccessToken(userId, accessToken);
    }


    //로그아웃
    @Transactional
    public void logout(String token) {

        userMapper.invalidateAccessToken(token);
    }

    //소셜유저 로그인
    @Transactional
    public String saveSocialUser(SocialUserDto socialUserDto, UserDto userDto, boolean link) {
        try {
            // 기존 사용자가 있는지 확인
            UserDto existingUser = userMapper.findByUserId(userDto.getUserId());

            if (existingUser == null) {
                // 신규 유저면 회원가입 처리
                userMapper.socialSave(userDto);
                socialUserMapper.save(socialUserDto);
                return "소셜 회원가입 성공";
            }

            // 폼 유저와 소셜 유저 자동 연동
            FormUserDto formUser = formUserMapper.findById(userDto.getEmail());
            if (formUser != null) {
                // 이미 연동된 소셜 유저가 없으면 자동으로 연동 처리
                SocialUserDto existingSocialUser = socialUserMapper.findByUserId(formUser.getUserId());
                if (existingSocialUser == null) {
                    socialUserDto.setUserId(formUser.getUserId());
                    socialUserMapper.save(socialUserDto);
                    return "소셜 로그인 & 폼 유저 자동 연동 성공";
                } else {
                    return "이미 연동된 회원입니다. 로그인 처리 진행.";
                }
            }

            // 기존 사용자인 경우, 토큰 정보 업데이트
            userMapper.updateAccessTokenAndRefreshToken(
                    userDto.getUserId(), userDto.getAccessToken(), userDto.getRefreshToken()
            );

            return "소셜 로그인 성공";
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("소셜 로그인 또는 연동 처리 중 오류가 발생하였습니다.", e);
        }
    }


    //@Transactional은 데이터베이스 작업을 하나의 작업 단위로 묶어준다.
    //폼회원가입
    @Transactional
    public void saveFormUser(FormUserDto formUserDto, UserDto userDto, boolean link, HttpServletResponse response) {
        try {
            // 기존 사용자인지 확인
            UserDto existingUser = userMapper.findByUserId(userDto.getUserId());
            if (existingUser == null) {
                // 1. 비밀번호 암호화
                String encodedPassword = bCryptPasswordEncoder.encode(formUserDto.getPasswd());
                formUserDto.setPasswd(encodedPassword);

                // 2. 토큰 생성 (Access Token 및 Refresh Token)
                String accessToken = jwtUtils.createAccessToken(userDto.getUserId());
                String refreshToken = jwtUtils.createRefreshToken(userDto.getUserId());
                userDto.setAccessToken(accessToken);
                userDto.setRefreshToken(refreshToken);

                // 3. 사용자 정보 저장
                userMapper.save(userDto);  // user 테이블에 삽입
                formUserMapper.save(formUserDto);  // formuser 테이블에 삽입

                // 4. 자동 연동 로직 수정
                SocialUserDto socialuser = socialUserMapper.findByEmail(userDto.getEmail());

                if (socialuser != null && socialuser.getEmail().equals(userDto.getEmail())) {
                    // 소셜 유저가 존재하고 이메일이 일치하면 연동 처리
                    socialuser.setUserId(formUserDto.getUserId());
                    socialUserMapper.save(socialuser);  // 소셜 유저 정보 업데이트
                    System.out.println("소셜 로그인 & 폼 유저 자동 연동 성공");
                }

                // 5. 토큰을 DB에 저장
                userMapper.updateAccessTokenAndRefreshToken(userDto.getUserId(), accessToken, refreshToken);

                // 6. JWT 토큰을 쿠키에 저장 (보안 속성 추가)
                Cookie accessTokenCookie = new Cookie("access_token", accessToken);
                accessTokenCookie.setHttpOnly(true);
                accessTokenCookie.setSecure(true);  // HTTPS에서만 전송
                accessTokenCookie.setMaxAge(3600);  // 1시간
                accessTokenCookie.setPath("/");
                response.addCookie(accessTokenCookie);
            } else {
                // 기존 사용자 예외 처리
                throw new RuntimeException("이미 존재하는 사용자입니다.");
            }
        } catch (Exception e) {
            // 예외 처리
            throw new RuntimeException("회원가입 처리 중 오류가 발생하였습니다.", e);
        }
    }


//리프레시토큰찾기
    public UserDto findByRefreshToken(String refreshToken) {
        return userMapper.findByRefreshToken(refreshToken);

    }


    //로그인한 상태에서 비밀번호 변경
    @Transactional
    public void changePassword(String userId, String oldPassword, String newPassword) {
        // 1. 폼 유저 확인 (비밀번호 검증)
        FormUserDto formUserDto = formUserMapper.findById(userId);
        if (formUserDto == null) {
            throw new RuntimeException("일반 로그인 사용자가 아닙니다.");
        }

        // 2. 기존 비밀번호 검증
        if (!bCryptPasswordEncoder.matches(oldPassword, formUserDto.getPasswd())) {
            throw new RuntimeException("기존 비밀번호가 일치하지 않습니다.");
        }

        // 3. 새 비밀번호가 비어있지 않은지 확인
        if (newPassword == null || newPassword.isEmpty()) {
            throw new RuntimeException("새 비밀번호가 비어있습니다.");
        }

        // 4. 새 비밀번호 암호화 및 업데이트
        String encodedPassword = bCryptPasswordEncoder.encode(newPassword);
        formUserMapper.findPassword(userId, encodedPassword);  // 비밀번호 업데이트

        // 5. UserDto를 사용해 토큰 갱신
        UserDto userDto = userMapper.findByUserId(userId);
        if (userDto == null) {
            throw new RuntimeException("사용자 정보를 찾을 수 없습니다.");
        }

        // 6. 새로운 토큰 생성
        String accessToken = jwtUtils.createAccessToken(userDto.getUserId());
        String refreshToken = jwtUtils.createRefreshToken(userDto.getUserId());

        // 7. 토큰 업데이트
        userMapper.updateAccessTokenAndRefreshToken(userDto.getUserId(), accessToken, refreshToken);
    }
}