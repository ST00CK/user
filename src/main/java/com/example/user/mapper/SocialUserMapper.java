package com.example.user.mapper;

import com.example.user.dto.FormUserDto;
import com.example.user.dto.SocialUserDto;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface SocialUserMapper {

    void save(SocialUserDto socialuserdto);

    SocialUserDto findByUserId(String user_id);

    // 소셜 로그인 유저가 존재하는지 확인하는 메서드

    boolean isSocialUser(String user_id);
}
