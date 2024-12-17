package com.example.user.dto;

import lombok.Data;

@Data
public class findPasswordRequestDto {

    private String userId; //사용자 아이디
    private String email; //사용자 이메일
    private String authCode; //이메일로 발송된 인증코드
    private String newPassword; //새로운 비밀번호
}
