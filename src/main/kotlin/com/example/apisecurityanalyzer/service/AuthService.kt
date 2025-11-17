package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.client.plugins.*
import io.ktor.http.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter

class AuthService(
    private val clientProvider: ClientProvider
) {
    private val mapper = jacksonObjectMapper()
    private val client: HttpClient get() = clientProvider.client

    @Volatile
    private var authToken: String? = null
    private val tokenMutex = Mutex()

    /**
     * Унифицированная функция выполнения запросов с автоматическим:
     * - добавлением Authorization: Bearer
     * - добавлением X-Requesting-Bank
     * - добавлением X-Consent-Id
     * - retry на 401 (получение банк-токена /auth/bank-token)
     */
    suspend fun performRequestWithAuth(
        method: HttpMethod,
        url: String,
        bankBaseUrl: String,
        clientId: String,
        clientSecret: String,
        consentId: String = "",
        bodyBlock: (HttpRequestBuilder.() -> Unit)? = null,
        issues: MutableList<Issue>? = null
    ): HttpResponse {

        suspend fun execute(token: String?): HttpResponse {
            return client.request(url) {
                this.method = method

                if (!token.isNullOrBlank()) {
                    header("Authorization", "Bearer $token")
                }

                header("X-Requesting-Bank", clientId)
                if (consentId.isNotBlank()) header("X-Consent-Id", consentId)

                header("Accept", "application/json")
                header("Accept-Charset", "UTF-8")
                header("User-Agent", "ApiSecurityAnalyzer/1.0")
                contentType(ContentType.Application.Json)

                bodyBlock?.invoke(this)
            }
        }

        val currentToken = authToken

        try {
            return execute(currentToken)
        } catch (e: ResponseException) {
            if (e.response.status.value == 401) {
                tokenMutex.withLock {
                    val newToken = fetchBankToken(bankBaseUrl, clientId, clientSecret, issues ?: mutableListOf())
                    if (!newToken.isNullOrBlank()) {
                        authToken = newToken
                    }
                }
                return execute(authToken)
            }
            throw e
        }
    }

    /**
     * Получение токена /auth/bank-token
     */
    suspend fun fetchBankToken(
        bankBaseUrl: String,
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue>
    ): String? {
        val tokenUrl = bankBaseUrl.trimEnd('/') + "/auth/bank-token"

        return try {
            val resp: HttpResponse = client.post(tokenUrl) {
                url {
                    parameters.append("client_id", clientId)
                    parameters.append("client_secret", clientSecret)
                }
                contentType(ContentType.Application.Json)
                setBody("{}")
            }

            if (!resp.status.isSuccess()) {
                addIssue(
                    issues,
                    Issue(
                        type = "TOKEN_HTTP_ERROR",
                        method = "POST",
                        path = tokenUrl,
                        severity = Severity.HIGH,
                        description = "Ошибка HTTP ${resp.status}",
                        evidence = resp.bodyAsText()
                    )
                )
                return null
            }

            val body = resp.bodyAsText()
            mapper.readTree(body).path("access_token").asText(null)

        } catch (ex: Exception) {
            addIssue(
                issues,
                Issue(
                    type = "TOKEN_EXCEPTION",
                    method = "POST",
                    path = tokenUrl,
                    severity = Severity.HIGH,
                    description = "Исключение при запросе bank-token",
                    evidence = ex.message ?: "unknown"
                )
            )
            null
        }
    }

    /**
     * Новый метод: возвращает текущий токен или запрашивает новый, если отсутствует
     */
    suspend fun getBankToken(
        bankBaseUrl: String,
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue> = mutableListOf()
    ): String {
        val token = authToken
        if (!token.isNullOrBlank()) return token

        val newToken = fetchBankToken(bankBaseUrl, clientId, clientSecret, issues)
        if (!newToken.isNullOrBlank()) {
            authToken = newToken
            return newToken
        }

        throw IllegalStateException("Не удалось получить bankToken")
    }

    /**
     * Реальный метод создания consent через /account-consents/request
     */
    suspend fun createConsent(
        bankBaseUrl: String,
        clientId: String,
        clientSecret: String,  // передаем сюда
        permissions: List<String>,
        expiresInHours: Long = 24,
        issues: MutableList<Issue>
    ): String {
        val token = getBankToken(bankBaseUrl, clientId, clientSecret, issues) // обязательно передаем clientSecret при первом запросе
        val consentUrl = "$bankBaseUrl/account-consents/request"

        val expiration = OffsetDateTime.now().plusHours(expiresInHours)
            .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)

        return try {
            val resp: HttpResponse = client.post(consentUrl) {
                header("Authorization", "Bearer $token")
                header("X-Requesting-Bank", clientId)
                contentType(ContentType.Application.Json)
                setBody(mapOf(
                    "client_id" to "$clientId-1",
                    "permissions" to permissions,
                    "expirationDateTime" to expiration
                ))
            }

            if (!resp.status.isSuccess()) {
                addIssue(
                    issues,
                    Issue(
                        type = "CONSENT_HTTP_ERROR",
                        method = "POST",
                        path = consentUrl,
                        severity = Severity.HIGH,
                        description = "Ошибка HTTP ${resp.status}",
                        evidence = resp.bodyAsText()
                    )
                )
                throw IllegalStateException("Не удалось создать consent")
            }

            val body = resp.bodyAsText()
            val consentId = mapper.readTree(body).path("consent_id").asText(null)
                ?: throw IllegalStateException("consent_id не найден в ответе")
            consentId
        } catch (ex: Exception) {
            addIssue(
                issues,
                Issue(
                    type = "CONSENT_EXCEPTION",
                    method = "POST",
                    path = consentUrl,
                    severity = Severity.HIGH,
                    description = "Исключение при создании consent",
                    evidence = ex.message ?: "unknown"
                )
            )
            throw ex
        }
    }


    private fun addIssue(list: MutableList<Issue>, issue: Issue) {
        if (list.none { it.type == issue.type && it.path == issue.path && it.method == issue.method }) {
            list.add(issue)
        }
    }
}
