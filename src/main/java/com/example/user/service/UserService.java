package com.example.user.service;

import com.example.user.dto.FormUserDto;
import com.example.user.dto.SocialUserDto;
import com.example.user.dto.UserDto;
import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.SocialUserMapper;
import com.example.user.mapper.UserMapper;
import com.example.user.util.JwtUtils;
import jakarta.mail.MessagingException;
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
    private final EmailService emailService;
    private final SocialUserMapper socialUserMapper;
    private final JwtUtils jwtUtils;


    //회원가입 메일전송 메서드
    private void sendAuthCodeEmail(String email, String authCode) throws MessagingException {
        emailService.sendEmail(email, authCode);
    }

    //비밀번호변경 메일전송 메서드
    private void sendPasswordFindEmail(String email, String authCode) throws MessagingException {
        emailService.sendPasswordFindEmail(email, authCode);
    }

    //폼유저 찾기
    public FormUserDto getUserById(String userId) {
        return formUserMapper.findById(userId);
    }

    //유저테이블에서 유저 찾기
    public UserDto findByUserId(String userId) {
        return userMapper.findByUserId(userId);
    }


    //로그아웃
    @Transactional
    public void logout(String token) {

        userMapper.invalidateAccessToken(token);
    }

    //폼회원가입
    @Transactional
    public void saveFormUser(FormUserDto formUserDto, UserDto userDto) {
        try {
            //기존 사용자가인지 확인
            UserDto existingUser = userMapper.findByUserId(userDto.getUserId());
            if (existingUser == null) {
                //비밀번호 암호화
                String encodedPassword = bCryptPasswordEncoder.encode(formUserDto.getPasswd());
                formUserDto.setPasswd(encodedPassword);

                //인증 코드 생성 및 이메일 전송
                String authCode = emailService.generateAuthCode();
                sendAuthCodeEmail(userDto.getEmail(), authCode);

//                // userDto의 user_id를 formUserDto에 설정
//                formUserDto.setUser_id(userDto.getUser_id());

                // user_id가 제대로 설정되었는지 확인
                System.out.println("떠라라라" + formUserDto.getUserId()); // user_id 확인

                //db에 저장
                userMapper.save(userDto); // user테이블에 삽입
                formUserMapper.save(formUserDto); //formuser테이블에 삽입

                //토큰을 db에 업데이트
                userMapper.updateAccessTokenAndRefreshToken(userDto.getUserId(), userDto.getAccessToken(), userDto.getRefreshToken());

            } else {
                throw new RuntimeException("이미 존재하는 사용자입니다.");
            }
        } catch (Exception e) {
            throw new RuntimeException("회원가입 처리 중 오류가 발생하였습니다.", e);
        }
    }

    //비밀번호 변경요청 이메일 인증 코드
    @Transactional
    public void findPassword(String userId, String email, String inputAuthCode, String newPasswd) throws MessagingException {
        UserDto userDto = userMapper.findByUserId(userId);
        if (userDto == null || !userDto.getEmail().equals(email)) {
            throw new RuntimeException("사용자 정보가 일치하지 않습니다");
        }
//        //인증코드 생성
//        String authCode = emailService.generateAuthCode();

        //테스트용
        String authCode = "123456";

        //인증코드 메일로 전송
        sendPasswordFindEmail(email, authCode);

        //입력된 인증 코드와 실제 인증 코드 비교
        if (!authCode.equals(inputAuthCode)) {
            throw new RuntimeException("인증코드가 일치하지 않습니다.");
        }
        String encodedPassword = bCryptPasswordEncoder.encode(newPasswd);

        //비밀번호 업데이트
        formUserMapper.findPassword(userId, encodedPassword);
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

    //소셜유저 로그인
    @Transactional
    public String saveSocialUser(SocialUserDto socialUserDto, UserDto userDto) {
        try {
            // 기존 사용자가 있는지 확인
            UserDto existingUser = userMapper.findByUserId(userDto.getUserId());

            if (existingUser == null) {
                // 사용자가 없으면 새로 삽입
                userMapper.socialSave(userDto); // UserDto 테이블에 저장
                socialUserMapper.save(socialUserDto); // SocialUserDto 테이블에 저장
            } else {
                // 사용자가 있으면 토큰 정보 업데이트
                userMapper.updateAccessTokenAndRefreshToken(
                        userDto.getUserId(), userDto.getAccessToken(), userDto.getRefreshToken()
                );
            }
            return "success";
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("회원가입 처리 중 오류가 발생하였습니다.", e);
        }
    }


}
