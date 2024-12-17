package com.example.user.service;

import com.example.user.dto.FormUserDto;
import com.example.user.dto.SocialUserDto;
import com.example.user.dto.UserDto;
import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.SocialUserMapper;
import com.example.user.mapper.UserMapper;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper; // 생성자 주입
    private final FormUserMapper formUserMapper; // 생성자 주입
    private final BCryptPasswordEncoder bCryptPasswordEncoder; // 생성자 주입
    private final EmailService emailService;
    private final SocialUserMapper socialUserMapper;


    //회원가입 메일전송 메서드
    private void sendAuthCodeEmail(String email, String authCode) throws MessagingException {
        emailService.sendEmail(email, authCode);
    }

    //비밀번호변경 메일전송 메서드
    private void sendPasswordFindEmail(String email, String authCode) throws MessagingException {
        emailService.sendPasswordFindEmail(email, authCode);
    }

    //폼로그인
    @Transactional
    public void saveFormUser(FormUserDto formUserDto, UserDto userDto) {
        try {
            //기존 사용자가인지 확인
            UserDto existingUser = userMapper.findByUserId(userDto.getUser_id());
            if (existingUser == null) {
                //비밀번호 암호화
                String encodedPassword = bCryptPasswordEncoder.encode(formUserDto.getPasswd());
                formUserDto.setPasswd(encodedPassword);

                //인증 코드 생성 및 이메일 전송
                String authCode = emailService.generateAuthCode();
                sendAuthCodeEmail(userDto.getEmail(), authCode);

                //db에 저장
                userMapper.save(userDto); // user테이블에 삽입
                formUserMapper.save(formUserDto); //formuser테이블에 삽입

                //토큰을 db에 업데이트
                userMapper.updateAccessTokenAndRefreshToken(userDto.getUser_id(), userDto.getAccess_token(), userDto.getRefresh_token());

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
        // 일반 로그인 사용자 확인
        FormUserDto formUserDto = formUserMapper.findByUserId(userId);
        if (formUserDto == null) {
            throw new RuntimeException("일반 로그인 사용자가 아닙니다.");
        }

        // 기존 비밀번호 검증
        if (!bCryptPasswordEncoder.matches(oldPassword, formUserDto.getPasswd())) {
            throw new RuntimeException("기존 비밀번호가 일치하지 않습니다.");
        }

        //새 비밀번호가 비어있지 않은지 확인
        if (newPassword == null || newPassword.isEmpty()) {
            throw new RuntimeException("새 비밀번호가 비어있습니다.");
        }

        // 새 비밀번호 암호화 및 업데이트
        String encodedPassword = bCryptPasswordEncoder.encode(newPassword);
        formUserMapper.findPassword(userId, encodedPassword);

        // 토큰 재발급 및 업데이트
        String newAccessToken = "newAccessToken"; // 실제 토큰 재발급 로직 추가
        String newRefreshToken = "newRefreshToken";
        userMapper.updateAccessTokenAndRefreshToken(userId, newAccessToken, newRefreshToken);
    }


    //소셜유저 로그인
    @Transactional
    public Mono<String> saveSocialUser(SocialUserDto socialUserDto, UserDto userDto) {
        try {
            //기존 사용자가인지 확인
            UserDto existingUser = userMapper.findByUserId(userDto.getUser_id());

            if (existingUser == null) {
                //사용자가 없으면 새로 삽입
                userMapper.socialSave(userDto); // UserDto 테이블에 저장
                socialUserMapper.save(socialUserDto); // SocialUserDto 테이블에 저장
            } else {
                //사용자가 있으면 토큰 정보 업데이트
                userMapper.updateAccessTokenAndRefreshToken(
                        userDto.getUser_id(), userDto.getAccess_token(), userDto.getRefresh_token()
                );
            }
            return Mono.just("success");
        } catch (Exception e) {
            e.printStackTrace();
            return Mono.error(new RuntimeException("회원가입 처리 중 오류가 발생하였습니다.", e));
        }
    }


}
