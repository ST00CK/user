# 빌드 단계: Java 17 JDK 기반의 Gradle 빌드 이미지
FROM openjdk:17-jdk AS build

# Gradle 설치
RUN apt-get update && apt-get install -y wget && \
    wget https://services.gradle.org/distributions/gradle-7.6-bin.zip -P /tmp && \
    unzip /tmp/gradle-7.6-bin.zip -d /opt && \
    ln -s /opt/gradle-7.6/bin/gradle /usr/bin/gradle

# 애플리케이션 소스 파일을 컨테이너로 복사
WORKDIR /app
COPY . .

# Gradle 빌드 실행
RUN gradle build --no-daemon

# 실행 단계: 경량 OpenJDK 17 이미지
FROM openjdk:17-jdk-slim

# 빌드된 JAR 파일을 실행 이미지로 복사
COPY --from=build /app/build/libs/*.jar /app/app.jar

# 포트 노출 (Spring Boot 기본 포트 8080)
EXPOSE 8080

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
