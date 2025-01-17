package com.example.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.ibatis.type.Alias;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {

    private String userId; //유저 고유 아이디
    private String name; //유저이름
    private String email; //이메일
    private String accessToken; //엑세스토큰
    private String refreshToken; //리프레시토큰
    private String file; //프로필사진
    private long accessTokenExpiry;  // 액세스 토큰 만료 시간
    private long refreshTokenExpiry; // 리프레시 토큰 만료 시간

    private List<String> roles;
}
