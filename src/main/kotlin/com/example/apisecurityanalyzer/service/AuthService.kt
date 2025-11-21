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
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import org.springframework.stereotype.Service

@Service
class AuthService(
    private val clientProvider: ClientProvider
) {
    private val mapper = jacksonObjectMapper()
    private val client: HttpClient get() = clientProvider.client

    @Volatile
    private var authToken: String? = null
    private val tokenMutex = Mutex()

    // -------------------------
    // Выполнение запроса с токеном и X-MDM-ID
    // -------------------------
    suspend fun performRequestWithAuth(
        method: HttpMethod,
        url: String,
        clientId: String,
        clientSecret: String,
        consentId: String = "",
        requireToken: Boolean = true,
        bodyBlock: (HttpRequestBuilder.() -> Unit)? = null,
        issues: MutableList<Issue>? = null
    ): HttpResponse {
        if (requireToken && (authToken.isNullOrBlank() || consentId.isBlank())) {
            throw IllegalStateException("Требуется токен/consentId для запроса $url")
        }

        suspend fun execute(token: String?): HttpResponse {
            return client.request(url) {
                this.method = method
                if (!token.isNullOrBlank()) header("Authorization", "Bearer $token")
                header("X-Requesting-Bank", clientId)
                if (consentId.isNotBlank()) header("X-Consent-Id", consentId)
                header("X-MDM-ID", "test-mdm-001")
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
                    val newToken = fetchOpenIdToken(clientId, clientSecret, issues ?: mutableListOf())
                    if (!newToken.isNullOrBlank()) authToken = newToken
                }
                return execute(authToken)
            }
            throw e
        }
    }

    // -------------------------
    // Получение OpenID токена
    // -------------------------
    suspend fun fetchOpenIdToken(
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue>
    ): String? {
        val tokenUrl =
            "https://auth.bankingapi.ru/auth/realms/kubernetes/protocol/openid-connect/token"
        return try {
            val resp: HttpResponse = client.post(tokenUrl) {
                contentType(ContentType.Application.FormUrlEncoded)
                setBody(
                    listOf(
                        "grant_type" to "client_credentials",
                        "client_id" to clientId,
                        "client_secret" to clientSecret
                    ).formUrlEncode()
                )
            }

            if (!resp.status.isSuccess()) {
                issues.add(
                    Issue(
                        "TOKEN_HTTP_ERROR",
                        Severity.HIGH,
                        "Ошибка HTTP ${resp.status}",
                        tokenUrl,
                        "POST",
                        resp.bodyAsText()
                    )
                )
                return null
            }

            mapper.readTree(resp.bodyAsText()).path("access_token").asText(null)
        } catch (ex: Exception) {
            issues.add(
                Issue(
                    "TOKEN_EXCEPTION",
                    Severity.HIGH,
                    "Исключение при запросе OpenID токена",
                    tokenUrl,
                    "POST",
                    ex.message ?: "unknown"
                )
            )
            null
        }
    }

    // -------------------------
    // Получение токена с кэшированием
    // -------------------------
    suspend fun getOpenIdToken(
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue> = mutableListOf()
    ): String {
        val token = authToken
        if (!token.isNullOrBlank()) return token
        val newToken = fetchOpenIdToken(clientId, clientSecret, issues)
        if (!newToken.isNullOrBlank()) {
            authToken = newToken
            return newToken
        }
        throw IllegalStateException("Не удалось получить OpenID token")
    }

    // -------------------------
    // Создание consent
    // -------------------------
    suspend fun createConsent(
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue>,
        permissions: List<String> = listOf(
            "ReadCards",
            "ReadAccountsBasic",
            "ReadAccountsDetail",
            "ReadBalances",
            "ManageAccounts",
            "ManageCards"
        )
    ): String {
        val token = getOpenIdToken(clientId, clientSecret, issues)
        val consentUrl = "https://api.bankingapi.ru/account-consents/request"
        val expiration = OffsetDateTime.now().plusHours(24).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)

        val requestBody = mapOf(
            "client_id" to "$clientId-1",
            "permissions" to permissions,
            "expirationDateTime" to expiration
        )

        val resp: HttpResponse = client.post(consentUrl) {
            header("Authorization", "Bearer $token")
            header("X-Requesting-Bank", clientId)
            header("X-MDM-ID", "test-mdm-001")
            contentType(ContentType.Application.Json)
            setBody(requestBody)
        }

        if (!resp.status.isSuccess()) {
            issues.add(
                Issue(
                    "CONSENT_HTTP_ERROR",
                    Severity.HIGH,
                    "Ошибка HTTP ${resp.status}",
                    consentUrl,
                    "POST",
                    resp.bodyAsText()
                )
            )
            throw IllegalStateException("Не удалось создать consent")
        }

        return mapper.readTree(resp.bodyAsText()).path("consent_id").asText()
            ?: throw IllegalStateException("consent_id не найден в ответе")
    }
}
