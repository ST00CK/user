package com.example.user.mapper;


import com.example.user.dto.SocialUserDto;
import org.apache.ibatis.annotations.Mapper;


@Mapper
public interface SocialUserMapper {

    void save(SocialUserDto socialuserdto);

    SocialUserDto findByUserId(String userId);

    SocialUserDto findByEmail(String email);



}
