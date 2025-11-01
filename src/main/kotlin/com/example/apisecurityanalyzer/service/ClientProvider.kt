package com.example.apianalyzer.service

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*

/**
 * Централизованный провайдер Ktor HttpClient.
 * Нужен для единой настройки, тестовой подмены (MockEngine) и контроля lifecycle клиента.
 */
class ClientProvider {
    val client: HttpClient = HttpClient(CIO) {
        install(HttpTimeout) {
            requestTimeoutMillis = 15_000
            connectTimeoutMillis = 10_000
            socketTimeoutMillis = 15_000
        }
        defaultRequest {
            header("User-Agent", "ApiSecurityAnalyzer/3.0")
            header("X-Scanner", "true")
        }
    }
}
