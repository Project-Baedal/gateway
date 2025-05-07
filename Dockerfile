FROM openjdk:21-jdk-slim AS builder
WORKDIR /app
COPY . .
RUN ./gradlew clean build

FROM openjdk:21-jdk-slim AS runner
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar gateway.jar
ENV TZ=Asia/Seoul
ENTRYPOINT ["java", "-jar", "gateway.jar"]

