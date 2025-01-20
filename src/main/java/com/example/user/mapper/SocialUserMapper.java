package com.example.user.mapper;

import com.example.user.dto.FormUserDto;
import com.example.user.dto.SocialUserDto;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface SocialUserMapper {

    void save(SocialUserDto socialuserdto);

    SocialUserDto findByUserId(String userId);




}
