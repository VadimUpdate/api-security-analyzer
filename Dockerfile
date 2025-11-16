# Используем официальный образ OpenJDK 17
FROM openjdk:17-jdk-slim

# Рабочая директория
WORKDIR /app

# Копируем файлы проекта
COPY build/libs/api-analyzer.jar api-analyzer.jar

# Экспонируем порт REST API
EXPOSE 8080

# Команда запуска Spring Boot приложения
ENTRYPOINT ["java","-jar","api-analyzer.jar"]
