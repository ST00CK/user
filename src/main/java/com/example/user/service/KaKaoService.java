package com.example.user.service;

import com.example.user.config.KaKaoConfig;
import com.example.user.dto.KaKaoDto;
import com.example.user.dto.SocialUserDto;
import com.example.user.dto.UserDto;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class KaKaoService {

    private final KaKaoConfig kakaoConfig;
    private final WebClient.Builder webClientBuilder;



    // 카카오 사용자 정보 가져오는 메소드
    public Mono<KaKaoDto> getKakaoUserInfo(String accessToken, String refreshToken) {
        String url = "https://kapi.kakao.com/v2/user/me";

        return webClientBuilder.build()
                .get()
                .uri(url + "?access_token=" + accessToken)
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        clientResponse -> clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody -> Mono.error(new RuntimeException("카카오 사용자 정보 조회 실패: " + errorBody))))
                .bodyToMono(String.class)
                .flatMap(response -> {
                    try {
                        ObjectMapper objectMapper = new ObjectMapper();
                        JsonNode jsonNode = objectMapper.readTree(response);

                        SocialUserDto socialUserDto = new SocialUserDto();
                        socialUserDto.setUser_id(jsonNode.get("id").asText());
                        socialUserDto.setProvider_type("KAKAO");

                        UserDto userDto = new UserDto();
                        userDto.setUser_id(jsonNode.get("id").asText());
                        userDto.setName(jsonNode.get("properties").get("nickname").asText());
                        userDto.setEmail(jsonNode.get("kakao_account").get("email").asText());
                        userDto.setAccess_token(accessToken);
                        userDto.setRefresh_token(refreshToken);  // 카카오에서 받은 리프레시 토큰을 함께 전달
                        userDto.setFile(jsonNode.get("properties").get("profile_image").asText());

                        KaKaoDto kaKaoDto = new KaKaoDto();
                        kaKaoDto.setSocialUserDto(socialUserDto);
                        kaKaoDto.setUserDto(userDto);

                        return Mono.just(kaKaoDto);
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("카카오 응답 파싱에 실패했습니다.", e));
                    }
                });
    }

    // 리프레시 토큰으로 새로운 액세스 토큰을 발급받는 메소드
    public Mono<TokenResponse> refreshAccessToken(String refreshToken) {
        String url = "https://kauth.kakao.com/oauth/token";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("client_id", kakaoConfig.getClientId());
        params.add("refresh_token", refreshToken);

        return webClientBuilder.build()
                .post()
                .uri(url)
                .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .bodyValue(params)
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        clientResponse -> clientResponse.bodyToMono(String.class)
                                .flatMap(errorBody -> Mono.error(new RuntimeException("카카오 API 호출 실패: " + errorBody))))
                .bodyToMono(String.class)
                .flatMap(response -> {
                    try {
                        ObjectMapper objectMapper = new ObjectMapper();
                        JsonNode jsonNode = objectMapper.readTree(response);

                        String accessToken = jsonNode.get("access_token").asText();
                        String newRefreshToken = jsonNode.has("refresh_token") ? jsonNode.get("refresh_token").asText() : refreshToken;

                        return Mono.just(new TokenResponse(accessToken, newRefreshToken));
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("리프레시 토큰으로 액세스 토큰을 발급받는 데 실패했습니다.", e));
                    }
                });
    }

    // 토큰 응답을 처리하기 위한 내부 클래스
    public static class TokenResponse {
        private final String accessToken;
        private final String refreshToken;

        public TokenResponse(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }
    }
}
