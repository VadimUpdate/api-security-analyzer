package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.service.AuthService
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.FuzzerService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class BuiltinCheckersPlugin(
    private val clientProvider: ClientProvider,
    private val authService: AuthService,
    val bankBaseUrl: String,
    val clientId: String,
    val clientSecret: String,
    private val enableFuzzing: Boolean = false,
    private val politenessDelayMs: Long = 150,
    private val maxConcurrency: Int = 4,
    private val maxPayloadsPerEndpoint: Int = 10
) {

    val name: String = "BuiltinCheckers"

    private val fuzzer = FuzzerService(
        authService = authService,
        bankBaseUrl = bankBaseUrl,
        clientId = clientId,
        clientSecret = clientSecret,
        enabled = enableFuzzing,
        politenessDelayMs = politenessDelayMs,
        maxConcurrency = maxConcurrency,
        maxPayloadsPerEndpoint = maxPayloadsPerEndpoint
    )

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

    private suspend fun checkIDOR(
        url: String,
        method: String,
        issues: MutableList<Issue>,
        consentId: String,
        bankToken: String
    ) {
        val altUrl = url.replace(Regex("/\\d+"), "/999999")
        try {
            val resp = authService.performRequestWithAuth(
                methodFromString(method),
                altUrl,
                bankBaseUrl,
                clientId,
                clientSecret,
                consentId = consentId,
                bankToken = bankToken,
                bodyBlock = null,
                issues = issues
            )
            if (resp.status.value in 200..299) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "IDOR",
                        severity = Severity.HIGH,
                        description = "Возможная IDOR уязвимость: доступ к чужому ресурсу",
                        path = url,
                        method = method
                    )
                )
            }
        } catch (_: Exception) { }
    }

    private suspend fun checkBrokenAuth(
        url: String,
        method: String,
        issues: MutableList<Issue>
    ) {
        try {
            val resp = clientProvider.client.request(url) {
                this.method = methodFromString(method)
            }
            if (resp.status.value in 200..299) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "BROKEN_AUTH",
                        severity = Severity.HIGH,
                        description = "Эндпоинт доступен без авторизации",
                        path = url,
                        method = method
                    )
                )
            }
        } catch (_: Exception) { }
    }

    suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>,
        consentId: String,
        bankToken: String,
        enableFuzzingOverride: Boolean = enableFuzzing
    ) {
        val httpMethod = methodFromString(method)
        val skipFuzzingCandidates = listOf("/health", "/metrics", "/ready", "/live", "/auth/bank-token")
        val fuzzingEnabled = enableFuzzing || enableFuzzingOverride

        try {
            val resp: HttpResponse = authService.performRequestWithAuth(
                httpMethod,
                url,
                bankBaseUrl,
                clientId,
                clientSecret,
                consentId = consentId,
                bankToken = bankToken,
                bodyBlock = null,
                issues = issues
            )
            val code = resp.status.value
            val body = resp.bodyAsText()

            if (code !in 200..399) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "ENDPOINT_ERROR_STATUS",
                        severity = if (code >= 500) Severity.HIGH else Severity.LOW,
                        description = "Эндпоинт $url вернул HTTP $code",
                        path = url,
                        method = method,
                        evidence = "HTTP $code"
                    )
                )
            }

            if (Regex("/\\d+").containsMatchIn(url) || url.endsWith("/1")) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "BOLA",
                        severity = Severity.MEDIUM,
                        description = "Публичный доступ к ресурсу по ID — потенциальная BOLA",
                        path = url,
                        method = method,
                        evidence = "HTTP $code"
                    )
                )
            }

            if (containsSensitiveField(body)) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "EXCESSIVE_DATA_EXPOSURE",
                        severity = Severity.HIGH,
                        description = "Ответ содержит возможные чувствительные поля",
                        path = url,
                        method = method,
                        evidence = body.take(300)
                    )
                )
            }

            // Auth checks
            checkIDOR(url, method, issues, consentId, bankToken)
            val requiresAuth = (operation.security?.isNotEmpty() == true)
            if (requiresAuth) checkBrokenAuth(url, method, issues)

            checkRateLimiting(url, httpMethod, issues, consentId, bankToken)

            if (fuzzingEnabled &&
                skipFuzzingCandidates.none { url.endsWith(it, ignoreCase = true) } &&
                operation.extensions?.get("x-scan-disabled") != true
            ) {
                try {
                    fuzzer.fuzzEndpoint(url, httpMethod, issues, consentId = consentId, bankToken = bankToken)
                } catch (_: Exception) { }
            }

        } catch (e: Exception) {
            addIfNotDuplicate(
                issues,
                Issue(
                    type = "NETWORK_ERROR",
                    severity = Severity.MEDIUM,
                    description = "Ошибка сети при $method $url: ${e.message}",
                    path = url,
                    method = method
                )
            )
        }
    }

    private fun addIfNotDuplicate(list: MutableList<Issue>, issue: Issue) {
        if (list.none { it.type == issue.type && it.path == issue.path && it.method == issue.method }) {
            list.add(issue)
        }
    }

    private suspend fun checkRateLimiting(
        url: String,
        method: HttpMethod,
        issues: MutableList<Issue>,
        consentId: String,
        bankToken: String
    ) {
        try {
            var triggered = false
            repeat(5) {
                val resp: HttpResponse = authService.performRequestWithAuth(
                    method,
                    url,
                    bankBaseUrl,
                    clientId,
                    clientSecret,
                    consentId = consentId,
                    bankToken = bankToken,
                    bodyBlock = null,
                    issues = issues
                )
                if (resp.status.value == 429) triggered = true
            }
            if (!triggered) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "RATE_LIMITING",
                        severity = Severity.MEDIUM,
                        description = "Эндпоинт не защищён rate limiting",
                        path = url,
                        method = method.value
                    )
                )
            }
        } catch (_: Exception) { }
    }
}
