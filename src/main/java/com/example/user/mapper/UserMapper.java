package com.example.user.mapper;

import com.example.user.dto.UserDto;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {

    void save (UserDto userDto);

    void socialSave(UserDto userDto);

    UserDto findByUserId(String user_id);

    void updateAccessTokenAndRefreshToken(String user_id, String access_token, String refresh_token);

    int invalidateAccessToken(String access_token);

}
