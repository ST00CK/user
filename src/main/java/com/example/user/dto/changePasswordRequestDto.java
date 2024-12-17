package com.example.user.dto;

import lombok.Data;

@Data
public class changePasswordRequestDto {



    private String userId; //사용자 아이디
    private String oldPassword; //기존 비밀번호
    private String newPassword; //새로운 비밀번호
}
