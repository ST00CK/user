package com.example.user.client;

import com.example.user.dto.UserDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@FeignClient(name = "userClient", url = "${user.service.url}")
public interface UserClient {

    @PostMapping("/friend/user/create")
    UserDto createUser(@RequestBody Map<String, String> request);


    @PostMapping("/friend/user/delete")
    void deleteUser(@RequestBody Map<String, String> request);
}


