package com.example.user.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class FormJwtUtils {

    //jwt기반 인증을 위한 토큰 생성, 검증, 갱신 기능을 제공
    //비밀키는 .env에서 환경변수로 불러들여와 초기화
    //액세스 토큰과 리프레시 토큰은 유효기간이 다르고, 각각의 역할에 따라 생성 및 검증이 됨

    @Value("${JWT_SECRET_KEY}")
    private String secretKeyString; // 기존에 환경변수나 프로퍼티에서 가져오는 문자열 키

    private SecretKey secretKey; // SecretKey 객체

    private static final long ACCESS_TOKEN_VALIDITY = 1000 * 60 * 60; // 1시간
    private static final long REFRESH_TOKEN_VALIDITY = 1000 * 60 * 60 * 24 * 7; // 7일

    //해당 메서드가 의존성 주입이 완료된 후, 초기화 작업을 수행하기 위해 호출되도록 지정하는 어노테이션
    @PostConstruct
    public void init() {
        this.secretKey = Keys.hmacShaKeyFor(secretKeyString.getBytes());//문자열 형태의 secretKeyString키를 secretkey 객체로 초기화
    }

    // 엑세스 토큰 생성
    public String createAccessToken(String username) { // username을 기반으로 액세스 토큰을 생성
        try {
            String token = Jwts.builder()
                    .setSubject(username) //토큰의 주체를 사용자 이름으로
                    .setIssuedAt(new Date()) //토큰 발행시간 설정
                    .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY)) //토큰 유효기간 설정
                    .signWith(secretKey, SignatureAlgorithm.HS256) // SecretKey 사용
                    .compact(); // jwt 문자열로 직렬화
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
                    .signWith(secretKey, SignatureAlgorithm.HS256) // SecretKey 사용
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
            return Jwts.parserBuilder() // 토큰 파서? 생성
                    .setSigningKey(secretKey) // SecretKey 사용
                    .build()
                    .parseClaimsJws(token) // 토큰을 파싱
                    .getBody(); //파싱된 토큰 반환
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
