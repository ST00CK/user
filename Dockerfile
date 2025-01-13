# 빌드 단계: Java 17 JDK 기반의 빌드 이미지
FROM openjdk:17-jdk AS build

# Gradle Wrapper를 사용하여 빌드를 진행
WORKDIR /app

# Gradle Wrapper 및 소스 파일 복사
COPY gradle /app/gradle
COPY gradlew /app/
COPY build.gradle /app/
COPY settings.gradle /app/
COPY src /app/src

# Gradle 빌드 실행 (필요한 경우, '--no-daemon' 추가 가능)
RUN ./gradlew build --no-daemon

# 실행 단계: 경량 실행용 OpenJDK 17 이미지
FROM openjdk:17-jdk-slim

# 빌드된 JAR 파일을 실행용 이미지로 복사
COPY --from=build /app/build/libs/*.jar /app/app.jar

# 포트 노출 (Spring Boot 기본 포트 8080)
EXPOSE 8080

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
