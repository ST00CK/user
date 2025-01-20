//package com.example.user.service;
//
//import com.example.user.dto.SocialUserDto;
//import com.example.user.dto.UserDto;
//import com.example.user.mapper.SocialUserMapper;
//import com.example.user.mapper.UserMapper;
//import com.example.user.util.JwtUtils;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Service;
//
//@Service
//@RequiredArgsConstructor
//public class OAuth2UserService {
//
//    private final SocialUserMapper socialUserMapper;
//    private final UserMapper userMapper;
//
//    // OAuth2 로그인 성공 후 처리
//    public UserDto processOAuth2User(String userId, String name, String email, String accessToken, String refreshToken, String providerType, String file) {
//        // 1. 소셜 로그인 유저가 이미 존재하는지 확인
//        SocialUserDto socialUser = socialUserMapper.findByUserId(userId);
//
//        if (socialUser == null) {
//            // 2. 새로운 유저일 경우 DB에 사용자 정보 저장
//            UserDto userDto = new UserDto(userId, name, email, accessToken, refreshToken, file, 0L, 0L, null); // file은 profileImageUrl로 설정
//            userMapper.socialSave(userDto);
//
//            // 3. 소셜 로그인 유저 정보 저장
//            socialUserMapper.save(new SocialUserDto(userId, providerType));
//
//            return userDto;
//        }
//
//        // 4. 이미 존재하는 경우 토큰 갱신
//        userMapper.updateAccessTokenAndRefreshToken(userId, accessToken, refreshToken);
//
//        // 5. 사용자 정보 반환
//        return userMapper.findByUserId(userId);
//    }
//}
