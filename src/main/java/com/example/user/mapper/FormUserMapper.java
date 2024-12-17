package com.example.user.mapper;

import com.example.user.dto.FormUserDto;
import com.example.user.dto.UserDto;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface FormUserMapper {

    void save(FormUserDto formuserdto);

    FormUserDto findByUserId(String user_id);

    void findPassword(String user_id, String passwd);
}
