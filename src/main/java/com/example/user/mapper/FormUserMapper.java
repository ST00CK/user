package com.example.user.mapper;

import com.example.user.dto.FormUserDto;
import com.example.user.dto.LoginDto;
import com.example.user.dto.UserDto;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface FormUserMapper {

    void save(FormUserDto formuserdto);

    FormUserDto findById(String userId);

    LoginDto findLoginUser(String userId);

    void findPassword(String userId, String passwd);

    FormUserDto findByUserId(String userId);


}
