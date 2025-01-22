package com.example.user.util;

import com.example.user.dto.UserDto;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import io.jsonwebtoken.security.Keys;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${JWT_SECRET_KEY}")
    private String secretKeyString; // 환경변수나 프로퍼티에서 가져옴

    private SecretKey secretKey; // SecretKey 객체

    private static final long ACCESS_TOKEN_VALIDITY = 1000 * 60 * 60; // 1시간
    private static final long REFRESH_TOKEN_VALIDITY = 1000 * 60 * 60 * 24 * 7; // 7일

    // SecretKey 초기화
    @PostConstruct
    public void init() {
        this.secretKey = Keys.hmacShaKeyFor(secretKeyString.getBytes());
    }

    // 엑세스 토큰 생성
    public String createAccessToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
                .signWith(secretKey, SignatureAlgorithm.HS256) // SecretKey 객체 사용
                .compact();
    }

    // 리프레시 토큰 생성
    public String createRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY))
                .signWith(secretKey, SignatureAlgorithm.HS256) // SecretKey 객체 사용
                .compact();
    }

    // 사용자 정보를 바탕으로 토큰 생성
    public String generateToken(UserDto userDto) {
        return createAccessToken(userDto.getUserId()); // user_id를 기반으로 accessToken 생성
    }
}
