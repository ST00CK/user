package com.example.user.mapper;

import com.example.user.dto.UserDto;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;


@Mapper
public interface UserMapper {

    void save (UserDto userDto);

    void socialSave(UserDto userDto);

    UserDto findByUserId(String userId);

    void updateAccessTokenAndRefreshToken(String userId, String accessToken, String refreshToken);

    void invalidateAccessToken(String accessToken);

    int updateProfileImage(String userId, String file);


}
