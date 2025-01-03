package com.example.user.util;

import com.example.user.dto.UserDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class formjwtutil {
    @Value("${JWT_SECRET_KEY}")
    private String secretKey; // 환경변수나 프로퍼티에서 가져옴

    private static final long ACCESS_TOKEN_VALIDITY = 1000 * 60 * 60; // 1시간
    private static final long REFRESH_TOKEN_VALIDITY = 1000 * 60 * 60 * 24 * 7; // 7일

    // 엑세스 토큰 생성
    public String createAccessToken(String username) {
        try {
            String token = Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
                    .signWith(SignatureAlgorithm.HS256, secretKey)
                    .compact();
            System.out.println("[DEBUG] Access Token 생성 완료: " + token);
            return token;
        } catch (Exception e) {
            System.out.println("[ERROR] Access Token 생성 실패: " + e.getMessage());
            throw e;
        }
    }

    // 리프레시 토큰 생성
    public String createRefreshToken(String username) {
        try {
            String token = Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY))
                    .signWith(SignatureAlgorithm.HS256, secretKey)
                    .compact();
            System.out.println("[DEBUG] Refresh Token 생성 완료: " + token);
            return token;
        } catch (Exception e) {
            System.out.println("[ERROR] Refresh Token 생성 실패: " + e.getMessage());
            throw e;
        }
    }

    // 토큰에서 클레임 정보 추출
    public Claims getClaims(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody();
            System.out.println("[DEBUG] 토큰에서 클레임 추출 완료: " + claims);
            return claims;
        } catch (ExpiredJwtException e) {
            System.out.println("[ERROR] 토큰 만료: " + e.getMessage());
            throw new IllegalArgumentException("Token has expired", e);
        } catch (Exception e) {
            System.out.println("[ERROR] 클레임 추출 실패: " + e.getMessage());
            throw new IllegalArgumentException("Invalid token", e);
        }
    }



    // 사용자 정보를 바탕으로 토큰 생성
    public String generateToken(UserDto userDto) {
        try {
            String token = createAccessToken(userDto.getUser_id());
            System.out.println("[DEBUG] 사용자 정보 기반 토큰 생성 완료: " + token);
            return token;
        } catch (Exception e) {
            System.out.println("[ERROR] 사용자 정보 기반 토큰 생성 실패: " + e.getMessage());
            throw e;
        }
    }
}