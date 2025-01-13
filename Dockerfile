# Gradle과 JDK를 포함한 이미지 사용 (Gradle 8.x로 변경)
FROM gradle:8.0-jdk17 AS build

# 작업 디렉토리 설정
WORKDIR /app

# 소스 코드 복사
COPY . .

# Gradle 빌드 실행
RUN gradle clean build --no-daemon

# 최종 이미지 설정 (필요에 따라 추가)
FROM openjdk:17
COPY --from=build /app/build/libs/User-0.0.1-SNAPSHOT.jar /app.jar

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "/app.jar"]
