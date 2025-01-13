FROM openjdk:17-alpine AS build

# 필수 도구만 설치
RUN apk add --no-cache bash

# 애플리케이션 소스 파일을 컨테이너로 복사
WORKDIR /app
COPY . .

# Gradle Wrapper를 사용하여 빌드 수행
RUN ./gradlew build --no-daemon

# 경량 OpenJDK 17 이미지
FROM openjdk:17-alpine

# 빌드된 JAR 파일을 실행 이미지로 복사
COPY --from=build /app/build/libs/*.jar /app/app.jar

# 포트 노출 (Spring Boot 기본 포트 8080)
EXPOSE 8080

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
