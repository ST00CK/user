package com.example.user.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class SessionCookieFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            Cookie sessionCookie = new Cookie("JSESSIONID", session.getId());
            sessionCookie.setHttpOnly(true); // 보안 설정 (XSS 방지)
            sessionCookie.setMaxAge(60 * 60);  // 1시간 유효
            sessionCookie.setPath("/");  // 전체 경로에서 유효하도록 설정
            response.addCookie(sessionCookie);
        }
        filterChain.doFilter(request, response); // 다음 필터로 넘김
    }
}
