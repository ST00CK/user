package com.example.user.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.beans.factory.annotation.Value;
import java.io.IOException;

public class SessionCookieFilter extends OncePerRequestFilter {

    @Value("${COOKIE_SAMESITE}") // 환경 변수 읽기
    private String sameSite;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Cookie sessionCookie = new Cookie("JSESSIONID", session.getId());
            sessionCookie.setHttpOnly(true);
            sessionCookie.setMaxAge(60 * 60);  // 1시간 유효
            sessionCookie.setPath("/");
            sessionCookie.setSecure(true);  // HTTPS 사용 시 true 설정 권장
            response.addCookie(sessionCookie);

            // SameSite 설정을 동적으로 적용
            String setCookieHeader = String.format("JSESSIONID=%s; HttpOnly; Max-Age=3600; Path=/; Secure; SameSite=%s", session.getId(), sameSite);
            response.setHeader("Set-Cookie", setCookieHeader);
        }
        filterChain.doFilter(request, response);
    }
}
