package com.example.user.util;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.*;

public class CustomHttpServletRequestWrapper extends HttpServletRequestWrapper {
    private final String body;

    public CustomHttpServletRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        // 요청 본문을 문자열로 읽어서 저장
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream(), request.getCharacterEncoding()))) {
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
        }
        this.body = stringBuilder.toString();
    }

    public String getBody() {
        return body;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(body.getBytes(getCharacterEncoding()));

        return new ServletInputStream() {
            @Override
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }

            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // 비동기 방식에 관련된 구현은 필요 없음
            }
        };
    }
}
