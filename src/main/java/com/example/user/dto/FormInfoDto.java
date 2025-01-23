package com.example.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FormInfoDto {

    private FormUserDto formUserDto;
    private UserDto userDto;
    private String authCode;  // 인증 코드 입력 필드 추가
}
