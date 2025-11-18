FROM eclipse-temurin:17-jdk

WORKDIR /app

# Создаем непривилегированного пользователя для безопасности
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 appuser

COPY certChecker.jar app.jar

# Меняем владельца файлов
RUN chown -R appuser:appgroup /app

# Переключаемся на непривилегированного пользователя
USER appuser

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]