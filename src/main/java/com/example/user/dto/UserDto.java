package com.example.user.dto;

import lombok.*;
import org.apache.ibatis.type.Alias;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder

public class UserDto {

    private String user_id; //유저 고유 아이디
    private String name; //유저이름
    private String email; //이메일
    private String access_token; //엑세스토큰
    private String refresh_token; //리프레시토큰
    private String file; //프로필사진
    private long access_token_expiry;  // 액세스 토큰 만료 시간
    private long refresh_token_expiry; // 리프레시 토큰 만료 시간

}
