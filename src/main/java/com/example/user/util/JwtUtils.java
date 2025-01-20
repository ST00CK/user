package com.example.user.util;

import com.example.user.dto.UserDto;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;

@Component
public class JwtUtils {

    @Value("${JWT_SECRET_KEY}")
    private String secretKey; // 환경변수나 프로퍼티에서 가져옴

    private static final long ACCESS_TOKEN_VALIDITY = 1000 * 60 * 60; // 1시간
    private static final long REFRESH_TOKEN_VALIDITY = 1000 * 60 * 60 * 24 * 7; // 7일

    // 엑세스 토큰 생성
    public String createAccessToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();


    }

    // 리프레시 토큰 생성
    public String createRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDITY))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    // 토큰에서 클레임 정보 추출
    public Claims getClaims(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException("Token has expired", e);
        } catch (UnsupportedJwtException e) {
            throw new IllegalArgumentException("Unsupported token", e);
        } catch (MalformedJwtException e) {
            throw new IllegalArgumentException("Malformed token", e);
        } catch (SignatureException e) {
            throw new IllegalArgumentException("Invalid signature", e);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid token", e);
        }
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            getClaims(token); // 클레임을 추출하면서 유효성을 검사
            return !isTokenExpired(token); // 토큰이 만료되지 않았는지 확인
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰이 만료되었는지 확인
    public boolean isTokenExpired(String token) {
        Claims claims = getClaims(token);
        return claims.getExpiration().before(new Date());
    }

    // 사용자 정보를 바탕으로 토큰 생성
    public String generateToken(UserDto userDto) {
        return createAccessToken(userDto.getUserId()); // user_id를 기반으로 accessToken을 생성
    }



}
