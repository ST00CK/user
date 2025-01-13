# 빌드 단계: Gradle을 사용하는 이미지
FROM gradle:8.0-jdk17 AS build

WORKDIR /app
COPY . .

# Debian/Ubuntu 기반이라면 apt-get으로 bash 설치
RUN apt-get update && apt-get install -y bash

# Gradle Wrapper를 사용해 빌드 수행
RUN ./gradlew build --no-daemon

# 실행 단계: OpenJDK 17 슬림 이미지 사용
FROM openjdk:17-slim

# 빌드된 JAR 파일을 실행 이미지로 복사
COPY --from=build /app/build/libs/*.jar /app/app.jar

# 애플리케이션 포트 노출 (Spring Boot 기본 포트 8080)
EXPOSE 8080

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
