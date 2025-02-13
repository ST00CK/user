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
        // multipart/form-data 요청이면 그냥 통과
        if (request.getContentType() != null && request.getContentType().startsWith("multipart/form-data")) {
            filterChain.doFilter(request, response);
            return;
        }
        // 요청이 들어오는 시점에 로그 추가
        logger.debug("Request received: " + request.getRequestURI());
        // 요청 본문을 래핑
        CustomHttpServletRequestWrapper wrappedRequest = new CustomHttpServletRequestWrapper(request);
        logger.debug("Request wrapped: " + wrappedRequest.getRequestURI());

        // 래핑된 요청을 다음 필터로 전달
        filterChain.doFilter(wrappedRequest, response);
    }
}