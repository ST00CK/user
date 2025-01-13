# 빌드 단계: OpenJDK 17 JDK를 기반으로 한 빌드 이미지
FROM openjdk:17-jdk AS build

# Gradle wrapper와 소스 파일 복사
WORKDIR /app
COPY gradlew .
COPY gradle gradle
COPY build.gradle settings.gradle ./
COPY src src/

# Gradle 의존성 설치 및 빌드 (테스트 제외)
RUN ./gradlew clean build -x test

# 최종 JAR 파일 경로 설정
ARG JAR_FILE=build/libs/*.jar

# 빌드된 JAR 파일을 production 단계로 복사
RUN cp $JAR_FILE app.jar

# 실행 단계: OpenJDK 17 JRE를 기반으로 한 경량 이미지
FROM openjdk:17-jre

# 작업 디렉토리 설정
WORKDIR /app

# 빌드 단계에서 생성된 JAR 파일을 production 이미지로 복사
COPY --from=build /app/app.jar app.jar

# 포트 노출 (Spring Boot 기본 포트 8080)
EXPOSE 8080

# Spring Boot 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "app.jar"]
