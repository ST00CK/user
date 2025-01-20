package com.example.user.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CustomRequestWrappingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 요청 본문을 래핑
        CustomHttpServletRequestWrapper wrappedRequest = new CustomHttpServletRequestWrapper(request);

        // 래핑된 요청을 다음 필터로 전달
        filterChain.doFilter(wrappedRequest, response);
    }
}