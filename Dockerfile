# 1단계: 빌드 단계 (Build stage)
FROM openjdk:17-jdk-slim AS build

WORKDIR /app

# Gradle Wrapper 관련 파일 복사
COPY gradlew gradlew.bat ./
COPY gradle/ ./gradle/

# 소스 코드 및 Gradle 설정 파일 복사
COPY build.gradle settings.gradle ./
COPY src ./src

# Gradle 빌드 실행
RUN chmod +x /app/gradlew
RUN ./gradlew clean build --no-daemon

# 2단계: 실행 단계 (Runtime stage)
FROM openjdk:17-jdk-slim

WORKDIR /app

# 빌드 스테이지에서 생성된 jar 파일 복사
COPY --from=build /app/build/libs/*SNAPSHOT.jar app.jar

# 포트 8090 열기
EXPOSE 8080

# 환경 변수를 런타임 이미지에 설정
ENV SPRING_PROFILES_ACTIVE=prod

# 애플리케이션 실행
CMD ["java", "-jar", "app.jar", "--spring.profiles.active=prod"]
