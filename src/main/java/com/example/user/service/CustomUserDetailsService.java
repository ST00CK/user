package com.example.user.service;

import com.example.user.dto.FormUserDto;
import com.example.user.dto.UserDto;
import com.example.user.mapper.FormUserMapper;
import com.example.user.mapper.UserMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserMapper userMapper;
    private final FormUserMapper formUserMapper;


    public CustomUserDetailsService(UserMapper userMapper, FormUserMapper formUserMapper) {
        this.userMapper = userMapper;
        this.formUserMapper = formUserMapper;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // FormUserDto에서 비밀번호 가져오기
        FormUserDto formUserDto = formUserMapper.findById(username); // userId를 사용
        if (formUserDto == null) {
            throw new UsernameNotFoundException("폼 사용자 정보를 찾을 수 없습니다: " + username);
        }

        // UserDetails 객체 생성
        return new org.springframework.security.core.userdetails.User(
                formUserDto.getUserId(),
                formUserDto.getPasswd(), // FormUserDto에서 비밀번호 가져오기
                // 권한 설정 (예: ROLE_USER)
                List.of(() -> "ROLE_USER") // 필요한 경우 권한을 추가
        );
    }

}