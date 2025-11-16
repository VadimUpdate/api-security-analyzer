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

class AuthService(
    private val clientProvider: ClientProvider
) {
    private val mapper = jacksonObjectMapper()
    private val client: HttpClient get() = clientProvider.client

    @Volatile
    private var authToken: String? = null
    private val tokenMutex = Mutex()

    suspend fun performRequestWithAuth(
        method: HttpMethod,
        url: String,
        bankBaseUrl: String,
        clientId: String,
        clientSecret: String,
        consentId: String = "",
        bankToken: String? = null,
        bodyBlock: (HttpRequestBuilder.() -> Unit)? = null,
        issues: MutableList<Issue>? = null
    ): HttpResponse {

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

                bodyBlock?.invoke(this)
            }
        }

        val current = bankToken ?: authToken

        try {
            return execute(current)
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

    suspend fun createConsent(clientId: String): String {
        return "${clientId}-consent-id"
    }

    private fun addIssue(list: MutableList<Issue>, issue: Issue) {
        if (list.none { it.type == issue.type && it.path == issue.path && it.method == issue.method }) {
            list.add(issue)
        }
    }
}
