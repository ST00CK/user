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
public class FormJwtUtill {
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

    // 토큰 유효성 검증
    public Claims validateToken(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            System.out.println("[ERROR] 토큰이 만료되었습니다: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            System.out.println("[ERROR] 토큰 검증 실패: " + e.getMessage());
            throw new RuntimeException("토큰 검증 실패");
        }
    }

    // 새로운 토큰 발급 로직
    public String refreshAccessToken(String refreshToken) {
        try {
            Claims claims = validateToken(refreshToken); // 리프레시 토큰 검증

            // 검증 후 새로운 액세스 토큰 생성
            String username = claims.getSubject();
            return createAccessToken(username);
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("리프레시 토큰이 만료되었습니다. 다시 로그인해야 합니다.");
        } catch (Exception e) {
            throw new RuntimeException("리프레시 토큰 검증 실패");
        }
    }


}