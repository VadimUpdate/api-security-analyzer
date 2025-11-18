package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.service.AuthService
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.FuzzerService
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation
import kotlinx.coroutines.*

class BuiltinCheckersPlugin(
    private val clientProvider: ClientProvider,
    private val authService: AuthService,
    private val bankBaseUrl: String,
    private val clientId: String,
    private val clientSecret: String,
    private val enableFuzzing: Boolean = true,
    private val politenessDelayMs: Long = 150L,
    private val maxConcurrency: Int = 4,
    private val maxPayloadsPerEndpoint: Int = 10
) : CheckerPlugin {

    override val name: String = "BuiltinCheckers"

    var consentId: String? = null
    var bankToken: String? = null

    val fuzzer: FuzzerService by lazy {
        FuzzerService(
            authService = authService,
            bankBaseUrl = bankBaseUrl,
            clientId = clientId,
            clientSecret = clientSecret,
            enabled = enableFuzzing,
            politenessDelayMs = politenessDelayMs,
            maxConcurrency = maxConcurrency,
            maxPayloadsPerEndpoint = maxPayloadsPerEndpoint
        ).apply {
            this.consentId = this@BuiltinCheckersPlugin.consentId ?: ""
            this.bankToken = this@BuiltinCheckersPlugin.bankToken ?: ""
        }
    }

    private fun methodFromString(m: String): HttpMethod = when (m.uppercase()) {
        "GET" -> HttpMethod.Get
        "POST" -> HttpMethod.Post
        "PUT" -> HttpMethod.Put
        "DELETE" -> HttpMethod.Delete
        "PATCH" -> HttpMethod.Patch
        "HEAD" -> HttpMethod.Head
        "OPTIONS" -> HttpMethod.Options
        else -> HttpMethod.Get
    }

    private fun containsSensitiveField(body: String?): Boolean {
        if (body.isNullOrBlank()) return false
        val sensitive = listOf("password", "token", "secret", "ssn", "creditCard", "dob")
        return sensitive.any { body.contains(it, ignoreCase = true) }
    }

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        try {
            val resp: HttpResponse? = try {
                authService.performRequestWithAuth(
                    methodFromString(method),
                    url,
                    bankBaseUrl,
                    clientId,
                    clientSecret,
                    consentId ?: "",
                    addClientIdToGet = false,
                    requireToken = true,
                    bodyBlock = { },
                    issues = issues
                )
            } catch (e: IllegalStateException) {
                if (e.message.orEmpty().contains("Требуется токен")) return
                else throw e
            }

            if (resp == null) return

            val code = resp.status.value
            val body = try { resp.bodyAsText() } catch (_: Throwable) { "" }

            if (code !in 200..399) {
                issues.add(Issue("ENDPOINT_ERROR_STATUS", if (code >= 500) Severity.HIGH else Severity.LOW,
                    "$method $url вернул HTTP $code", url, method))
            }

            if (containsSensitiveField(body)) {
                issues.add(Issue("EXCESSIVE_DATA_EXPOSURE", Severity.HIGH,
                    "Ответ содержит чувствительные поля", url, method))
            }

            if (method.equals("GET", true) || method.equals("HEAD", true)) {
                if (Regex("/\\d+").containsMatchIn(url) || url.endsWith("/1")) {
                    issues.add(Issue("BOLA", Severity.MEDIUM,
                        "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA, HTTP $code",
                        url, method))
                    issues.add(Issue("IDOR", Severity.MEDIUM,
                        "Возможен IDOR, проверка доступа к чужим объектам", url, method))
                }
            }

            if (body.contains("invalid token", ignoreCase = true) ||
                body.contains("expired", ignoreCase = true)) {
                issues.add(Issue("BROKEN_AUTH", Severity.HIGH,
                    "Возможна уязвимость Broken Authentication", url, method))
            }

            checkRateLimiting(url, methodFromString(method), issues)

            if (enableFuzzing) {
                fuzzer.bankToken = bankToken ?: ""
                fuzzer.consentId = consentId ?: ""
                fuzzer.fuzzEndpoint(url, methodFromString(method), issues)
            }

        } catch (e: Exception) {
            if (!e.message.orEmpty().contains("Требуется токен")) {
                issues.add(Issue("NETWORK_ERROR", Severity.MEDIUM,
                    "Ошибка сети при $method $url: ${e.message}", url, method))
            }
        }
    }

    private suspend fun checkRateLimiting(url: String, method: HttpMethod, issues: MutableList<Issue>) {
        try {
            var triggered = false
            repeat(5) {
                val resp: HttpResponse? = try {
                    authService.performRequestWithAuth(
                        method,
                        url,
                        bankBaseUrl,
                        clientId,
                        clientSecret,
                        consentId ?: "",
                        addClientIdToGet = false,
                        requireToken = true,
                        bodyBlock = { },
                        issues = issues
                    )
                } catch (e: IllegalStateException) {
                    if (e.message.orEmpty().contains("Требуется токен")) return
                    else throw e
                }

                if (resp == null) return

                if (resp.status.value == 429) triggered = true
            }
            if (!triggered) {
                issues.add(Issue("RATE_LIMITING", Severity.MEDIUM,
                    "Эндпоинт $url не защищен rate limiting", url, method.value))
            }
        } catch (_: Exception) { }
    }
}
