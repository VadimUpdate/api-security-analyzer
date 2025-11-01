package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.client.plugins.*
import io.ktor.http.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Вынесённая логика аутентификации + retry на 401.
 *
 * Сохраняет поведение оригинала: хранит authToken, при 401 пытается получить новый токен,
 * использует tokenMutex для синхронизации.
 */
class AuthService(private val clientProvider: ClientProvider) {
    private val mapper = jacksonObjectMapper()
    private val client: HttpClient get() = clientProvider.client

    @Volatile
    var authToken: String? = null
    private val tokenMutex = Mutex()

    /**
     * Выполнить запрос с возможной авторизацией. При 401 — попытка обновить токен (best-effort).
     * Возвращает HttpResponse или пробрасывает исключение (как в оригинале).
     */
    suspend fun performRequestWithAuth(
        method: HttpMethod,
        url: String,
        authClientId: String,
        authClientSecret: String,
        bodyBlock: (HttpRequestBuilder.() -> Unit)? = null,
        issues: MutableList<Issue>
    ): HttpResponse {
        suspend fun doRequest(token: String?): HttpResponse {
            return client.request(url) {
                this.method = method
                token?.let { header("Authorization", "Bearer $it") }
                bodyBlock?.invoke(this)
            }
        }

        val cur = authToken
        try {
            return doRequest(cur)
        } catch (e: ResponseException) {
            val status = try { (e.response as? HttpResponse)?.status?.value } catch (_: Exception) { null }
            if (status == 401) {
                // попытаться получить новый токен (synchronized)
                tokenMutex.withLock {
                    val newToken = obtainBearerTokenFromSpecOrFallback(null, url, authClientId, authClientSecret, issues)
                    if (!newToken.isNullOrBlank()) authToken = newToken
                }
                return doRequest(authToken)
            } else throw e
        }
    }

    /**
     * Best-effort получение client_credentials токена с /oauth/token на базовом URL.
     * Возвращает access_token или null (и добавляет ISSUE).
     */
    suspend fun obtainBearerTokenFromSpecOrFallback(
        openApi: io.swagger.v3.oas.models.OpenAPI?,
        baseUrlCandidate: String,
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue>
    ): String? {
        return try {
            val tokenUrl = baseUrlCandidate.trimEnd('/') + "/oauth/token"
            val resp: HttpResponse = client.submitForm(
                url = tokenUrl,
                formParameters = Parameters.build {
                    append("grant_type", "client_credentials")
                    append("client_id", clientId)
                    append("client_secret", clientSecret)
                },
                encodeInQuery = false
            )
            val body = resp.bodyAsText()
            mapper.readTree(body).get("access_token")?.asText()
        } catch (e: Exception) {
            addIfNotDuplicate(
                issues,
                Issue(
                    "TOKEN_ERROR",
                    baseUrlCandidate,
                    "POST",
                    "HIGH",
                    "Не удалось получить токен",
                    e.message ?: "unknown"
                )
            )
            null
        }
    }

    private fun addIfNotDuplicate(issues: MutableList<Issue>, i: Issue) {
        if (issues.none { it.type == i.type && it.path == i.path && it.method == i.method }) issues += i
    }
}
