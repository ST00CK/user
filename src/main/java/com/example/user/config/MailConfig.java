package com.example.user.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.util.Properties;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class MailConfig {

    @Value("${SMTP_HOST}")
    private String smtpHost;

    @Value("${SMTP_PORT}")
    private int smtpPort;

    @Value("${SMTP_USERNAME}")
    private String smtpUsername;

    @Value("${SMTP_PASSWORD}")
    private String smtpPassword;

    @Value("${SMTP_FROM}")
    private String smtpFrom;

    @Bean
    public JavaMailSender javaMailService() {
        JavaMailSenderImpl javaMailSender = new JavaMailSenderImpl();

        javaMailSender.setHost(smtpHost);
        javaMailSender.setPort(smtpPort);
        javaMailSender.setUsername(smtpUsername);
        javaMailSender.setPassword(smtpPassword);
        javaMailSender.setJavaMailProperties(getMailProperties());
        javaMailSender.setDefaultEncoding("UTF-8");

        return javaMailSender;


    }

    private Properties getMailProperties() {
        Properties properties = new Properties();

        //프로토콜 설정
        properties.setProperty("mail.transport.protocol", "smtp");

        //SMTP 인증
        properties.setProperty("mail.smtp.auth", "true");

        // TLS 사용
        properties.setProperty("mail.smtp.starttls.enable", "true");

        //디버그 모드 활성화 (개발중에만 사용) 운영상태일때는 false로 변경 요망
        properties.setProperty("mail.debug", "true");

        //SSL 설정
        properties.setProperty("mail.smtp.ssl.trust", "smtp.naver.com");
        properties.setProperty("mail.smtp.ssl.enable", "true");
        return properties;
    }
}
