# Gradle 빌드 스테이지
FROM gradle:8.0-jdk17 AS build

# 작업 디렉토리 설정
WORKDIR /app

# Gradle 관련 파일만 복사 (의존성 캐시 활용)
COPY gradle ./gradle
RUN gradle dependencies --no-daemon

# 소스 코드 복사 후 빌드
COPY . .
RUN gradle clean build --no-daemon

# 최종 이미지
FROM openjdk:17-slim
WORKDIR /app

# JAR 파일 복사
COPY --from=build /app/build/libs/User-0.0.1-SNAPSHOT.jar /app.jar

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "/app.jar"]
