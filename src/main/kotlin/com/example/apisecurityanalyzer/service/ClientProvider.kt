package com.example.apianalyzer.service

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.jackson.*
import org.springframework.stereotype.Service

/**
 * Централизованный провайдер Ktor HttpClient.
 * Поддерживает таймауты, логирование, JSON-сериализацию и базовые заголовки.
 * Автоматически добавляет X-MDM-ID для тестовых запросов к /products и /pmnt/acceptance/mobile.
 */
@Service
class ClientProvider {

    val client: HttpClient = HttpClient(CIO) {

        install(HttpTimeout) {
            requestTimeoutMillis = 15_000
            connectTimeoutMillis = 10_000
            socketTimeoutMillis = 15_000
        }

        install(Logging) {
            level = LogLevel.ALL
            logger = object : Logger {
                override fun log(message: String) {
                    println("[HTTP] $message")
                }
            }
        }

        install(ContentNegotiation) {
            jackson()
        }

        defaultRequest {
            header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            header("X-Scanner", "true")

            // Заглушка: автоматически добавляем X-MDM-ID для известных эндпоинтов
            val path = url.toString()
            if (path.contains("/products") || path.contains("/pmnt/acceptance/mobile")) {
                header("X-MDM-ID", "test-mdm-001")
            }
        }
    }
}
