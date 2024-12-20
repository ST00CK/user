package com.example.user.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebClientConfig {
//    @Bean
//    public WebMvcConfigurer corsConfigurer() {
//        return new WebMvcConfigurer() {
//            @Override
//            public void addCorsMappings(CorsRegistry registry) {
//                registry.addMapping("/**") // 모든 경로에 대해
//                        .allowedOrigins("http://localhost:3000") // React 앱의 출처
//                        .allowedMethods("GET", "POST", "PUT", "DELETE") // 허용할 HTTP 메서드
//                        .allowedHeaders("*") // 모든 헤더 허용
//                        .allowCredentials(true); // 인증 정보 허용
//            }
//        };
//    }
    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }
}
