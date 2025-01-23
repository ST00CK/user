package com.example.user.dto;

import lombok.Data;

@Data
public class VerifyEmailDto {
    private FormUserDto formUserDto;
    private UserDto userDto;
    private String authCode;  // 사용자 입력 인증 코드
    private String email;
}
