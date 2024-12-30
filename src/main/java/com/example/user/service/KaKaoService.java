package com.example.user.service;

import com.example.user.config.KaKaoConfig;
import com.example.user.dto.KaKaoDto;
import com.example.user.dto.SocialUserDto;
import com.example.user.dto.UserDto;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpMethod;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;


@Service
public class KaKaoService {

    private static final Logger log = LoggerFactory.getLogger(KaKaoService.class);

    private final KaKaoConfig kakaoConfig;
    private final RestTemplate restTemplate;

    public KaKaoService(KaKaoConfig kakaoConfig, RestTemplate restTemplate) {
        this.kakaoConfig = kakaoConfig;
        this.restTemplate = restTemplate;
    }


    // 카카오 사용자 정보 가져오는 메소드
    public KaKaoDto getKakaoUserInfo(String accessToken, String refreshToken) {
        System.out.println("액세스 토큰: " + accessToken);
        System.out.println("리프레시: " + refreshToken);
        boolean isValid = validateKakaoAccessToken(accessToken);
        System.out.println("액세스 토큰 유효성 검사 결과: " + isValid);

        if (!isValid) {
            // 토큰이 유효하지 않으면 리프레시 토큰을 사용하여 새 액세스 토큰 발급
            TokenResponse tokenResponse = refreshTokens(refreshToken);
            System.out.println("새로운 액세스 토큰: " + tokenResponse.getAccessToken());
            return fetchKakaoUserInfo(tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
        }

        // 액세스 토큰이 유효하면 바로 사용자 정보 조회
        return fetchKakaoUserInfo(accessToken, refreshToken);
    }

    // 카카오 사용자 정보 요청 메소드
    public KaKaoDto fetchKakaoUserInfo(String accessToken, String refreshToken) {

        log.debug("Kakao Client ID: {}", kakaoConfig.getClientId());
        log.debug("Kakao Client Secret: {}", kakaoConfig.getClientSecret());
        log.debug("Kakao Redirect URI: {}", kakaoConfig.getRedirectUri());
        System.out.println("카카오 사용자 정보 요청 중, 액세스 토큰: " + accessToken);
        System.out.println("리프레시토큰떠라: " + refreshToken); // null 여부 확인

        String url = "https://kapi.kakao.com/v2/user/me";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken); // 헤더에 액세스 토큰 추가
        HttpEntity<String> entity = new HttpEntity<>(headers); // HttpEntity로 요청 보냄

        try {
            String response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class).getBody(); // exchange 메서드 사용

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(response);

            // SocialUserDto 설정
            SocialUserDto socialUserDto = new SocialUserDto();
            socialUserDto.setUser_id(jsonNode.get("id").asText());
            socialUserDto.setProvider_type("KAKAO");

            // UserDto 설정
            UserDto userDto = new UserDto();
            userDto.setUser_id(jsonNode.get("id").asText());
            userDto.setName(jsonNode.get("properties").get("nickname").asText());
            userDto.setEmail(jsonNode.get("kakao_account").get("email").asText());
            userDto.setAccess_token(accessToken); // access_token을 UserDto에만 설정
            userDto.setRefresh_token(refreshToken); // refresh_token을 UserDto에만 설정
            userDto.setFile(jsonNode.get("properties").get("profile_image").asText());

            // KaKaoDto에 UserDto와 SocialUserDto 설정
            KaKaoDto kaKaoDto = new KaKaoDto();
            kaKaoDto.setSocialUserDto(socialUserDto);
            kaKaoDto.setUserDto(userDto);

            System.out.println("카카오 사용자 정보: " + kaKaoDto);

            return kaKaoDto;

        } catch (Exception e) {
            log.error("카카오 응답 파싱에 실패했습니다.", e);
            throw new RuntimeException("카카오 응답 파싱에 실패했습니다.", e);
        }
    }

    public TokenResponse refreshTokens(String refreshToken) {

        String url = "https://kauth.kakao.com/oauth/token";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("client_id", kakaoConfig.getClientId());
        params.add("refresh_token", refreshToken);

        try {
            // API 호출하여 새로운 액세스 토큰과 리프레시 토큰을 받음
            TokenResponse tokenResponse = restTemplate.postForObject(url, params, TokenResponse.class);

            // 새로운 리프레시 토큰이 포함된 응답이 오지 않으면 예외 발생
            if (tokenResponse == null || tokenResponse.getAccessToken() == null || tokenResponse.getRefreshToken() == null) {
                throw new RuntimeException("새로운 액세스 토큰 및 리프레시 토큰 발급 실패");
            }

            return tokenResponse;

        } catch (Exception e) {
            log.error("토큰 갱신 실패", e);
            throw new RuntimeException("토큰 갱신 실패", e);
        }
    }


    public boolean validateKakaoAccessToken(String accessToken) {
        String url = "https://kapi.kakao.com/v1/user/access_token_info";

        try {
            // HTTP 헤더 설정
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(headers);

            // API 호출
            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            // 응답 파싱
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(response.getBody());

            // 응답에 "id" 필드가 존재하면 유효한 토큰
            if (jsonNode.has("id")) {
                return true;
            } else {
                log.error("유효하지 않은 토큰: id 없음");
                return false;
            }
        } catch (HttpClientErrorException e) {
            log.error("토큰 검증 실패 - HTTP 오류", e);
            return false; // 토큰이 유효하지 않음
        } catch (Exception e) {
            log.error("토큰 검증 실패", e);
            throw new RuntimeException("토큰 검증 실패", e);
        }
    }


    public class TokenResponse {
        private String accessToken;
        private String refreshToken;

        // Getter, Setter, and other methods

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }
    }

}
