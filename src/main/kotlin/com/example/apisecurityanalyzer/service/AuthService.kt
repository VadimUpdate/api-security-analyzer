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

    /**
     * Унифицированная функция выполнения запросов с автоматическим:
     * - добавлением Authorization: Bearer
     * - добавлением X-Requesting-Bank
     * - добавлением X-Consent-Id
     * - добавлением client_id в GET/POST/PUT/PATCH
     * - retry на 401 (получение банк-токена)
     *
     * @param requireToken - если true, запретить выполнение запроса без токена/consentId
     */
    suspend fun performRequestWithAuth(
        method: HttpMethod,
        url: String,
        bankBaseUrl: String,
        clientId: String,
        clientSecret: String,
        consentId: String = "",
        addClientIdToGet: Boolean = true,
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
                header("Accept", "application/json")
                header("Accept-Charset", "UTF-8")
                header("User-Agent", "ApiSecurityAnalyzer/1.0")
                contentType(ContentType.Application.Json)

                if (addClientIdToGet && method in listOf(HttpMethod.Get, HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch)) {
                    url { parameters.append("client_id", clientId) }
                }

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
                    if (!newToken.isNullOrBlank()) authToken = newToken
                }
                return execute(authToken)
            }
            throw e
        }
    }

    suspend fun fetchBankToken(
        bankBaseUrl: String,
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue>
    ): String? {
        val tokenUrl = bankBaseUrl.trimEnd('/') + "/auth/bank-token"
        return try {
            val resp: HttpResponse = client.post(tokenUrl) {
                url { parameters.append("client_id", clientId); parameters.append("client_secret", clientSecret) }
                contentType(ContentType.Application.Json)
                setBody("{}")
            }
            if (!resp.status.isSuccess()) {
                issues.add(Issue("TOKEN_HTTP_ERROR", Severity.HIGH, "Ошибка HTTP ${resp.status}", tokenUrl, "POST", resp.bodyAsText()))
                return null
            }
            mapper.readTree(resp.bodyAsText()).path("access_token").asText(null)
        } catch (ex: Exception) {
            issues.add(Issue("TOKEN_EXCEPTION", Severity.HIGH, "Исключение при запросе bank-token", tokenUrl, "POST", ex.message ?: "unknown"))
            null
        }
    }

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

    suspend fun createConsent(
        bankBaseUrl: String,
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue>,
        permissions: List<String> = listOf("ReadCards","ReadAccountsBasic","ReadAccountsDetail","ReadBalances","ManageAccounts","ManageCards")
    ): String {
        val token = getBankToken(bankBaseUrl, clientId, clientSecret, issues)
        val consentUrl = "$bankBaseUrl/account-consents/request"
        val expiration = OffsetDateTime.now().plusHours(24).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)

        val requestBody = mapOf(
            "client_id" to "$clientId-1",
            "permissions" to permissions,
            "expirationDateTime" to expiration
        )

        val resp: HttpResponse = client.post(consentUrl) {
            header("Authorization", "Bearer $token")
            header("X-Requesting-Bank", clientId)
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
