package com.example.user.util;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

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
    public boolean isTokenExpired(String token) {
        Claims claims = getClaims(token);
        return claims.getExpiration().before(new Date());
    }

    // 토큰에서 사용자명 추출
    public String getUsername(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }
}
