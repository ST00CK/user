# Gradle 빌드 스테이지
FROM gradle:8.0-jdk17 AS build

# 작업 디렉토리 설정
WORKDIR /app

# Gradle 및 빌드 파일 복사
COPY gradle ./gradle
COPY build.gradle settings.gradle ./

# 의존성 캐시 생성
RUN gradle build --no-daemon -x test

# 소스 코드 복사 및 빌드
COPY . .
RUN gradle clean build --no-daemon

# 최종 이미지
FROM openjdk:17-slim
WORKDIR /app

# JAR 파일 복사
COPY --from=build /app/build/libs/User-0.0.1-SNAPSHOT.jar /app/app.jar

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
