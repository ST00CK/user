//package com.example.user.util;
//
//import jakarta.servlet.*;
//import jakarta.servlet.http.HttpServletRequest;
//import org.springframework.web.multipart.MultipartHttpServletRequest;
//
//import java.io.IOException;
//
//public class CustomMultipartFilter implements Filter {
//
//    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
//        if (request instanceof HttpServletRequest) {
//            HttpServletRequest httpRequest = (HttpServletRequest) request;
//            if (httpRequest instanceof MultipartHttpServletRequest) {
//                // 이미 MultipartHttpServletRequest인 경우 바로 통과시킴
//                chain.doFilter(request, response);
//            } else {
//                // MultipartHttpServletRequest로 변환되지 않은 경우, 그대로 통과시킴
//                chain.doFilter(request, response);
//            }
//        } else {
//            chain.doFilter(request, response);
//        }
//    }
//}
