package com.example.user.client;

import com.example.user.dto.UserDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "userClient", url = "${user.service.url}")
public interface UserClient {

    @GetMapping("/user/{userId}")
    UserDto getUserInfo(@PathVariable("userId") String userId);  // 다른 서비스의 API 호출
}


