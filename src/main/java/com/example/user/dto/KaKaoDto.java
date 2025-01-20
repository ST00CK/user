package com.example.user.dto;

import lombok.Data;

@Data
public class KaKaoDto {
    private SocialUserDto socialUserDto; // 카카오 사용자 정보
    private UserDto userDto; // 카카오 사용자 상세 정보
}
