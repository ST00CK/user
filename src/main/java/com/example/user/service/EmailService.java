package com.example.user.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

   @Value("${smtp.from}")
   private String fromEmail;

    //인증코드 생성
    public String generateAuthCode() {
        Random random = new Random();
        StringBuilder authCode = new StringBuilder();

        for (int i = 0; i < 8; i++) {
            int index = random.nextInt(3);
            switch (index) {
                case 0:
                    authCode.append((char) (random.nextInt(26) + 97)); // a~z
                    break;
                case 1:
                    authCode.append((char) (random.nextInt(26) + 65)); // A~Z
                    break;
                case 2:
                    authCode.append(random.nextInt(10)); // 0~9
                    break;
            }
        }

        return authCode.toString();
    }

    //회원가입 메일
    public void  sendEmailAndSaveAuthCode(String to, String authCode, HttpSession session) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

        helper.setTo(to);
        helper.setSubject("회원가입 인증 이메일");
        helper.setText(
                "<h1>이메일 인증</h1>" +
                        "<p>본인인증 코드: " + authCode + "</p>",
                true
        );
        helper.setFrom(fromEmail);

        mailSender.send(message);

        // 인증 코드를 세션에 저장
        session.setAttribute("authCode", authCode);
    }

    //비밀번호 변경 메서드
    public void sendPasswordFindEmail(String to, String authCode, HttpSession session) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

        helper.setTo(to);
        helper.setSubject("비밀번호 변경 이메일");
        helper.setText(
                "<h1>비밀번호 변경 인증</h1>" +
                        "<p>본인인증 코드: " + authCode + "</p>",
                true
        );
        helper.setFrom(fromEmail);

        mailSender.send(message);
        // 인증 코드를 세션에 저장
        session.setAttribute("authCode", authCode);
    }
}