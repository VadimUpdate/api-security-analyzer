package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.service.AuthService
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.FuzzerService
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class BuiltinCheckersPlugin(
    private val clientProvider: ClientProvider,
    private val authService: AuthService,
    private val bankBaseUrl: String,
    private val clientId: String,
    private val clientSecret: String,
    private val enableFuzzing: Boolean = false,
    private val politenessDelayMs: Long = 150L,
    private val maxConcurrency: Int = 4,
    private val maxPayloadsPerEndpoint: Int = 10
) : CheckerPlugin {

    override val name: String = "BuiltinCheckers"

    var bankToken: String = ""
    var consentId: String = ""

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

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        try {
            // Проверяем, что токен и consent установлены
            if (bankToken.isBlank()) throw IllegalStateException("bankToken не установлен в BuiltinCheckersPlugin")
            if (consentId.isBlank()) throw IllegalStateException("consentId не установлен в BuiltinCheckersPlugin")

            val resp: HttpResponse = authService.performRequestWithAuth(
                method = methodFromString(method),
                url = url,
                bankBaseUrl = bankBaseUrl,
                clientId = clientId,
                clientSecret = clientSecret,
                consentId = consentId,
                bodyBlock = { /* нет тела */ },
                issues = issues
            )

            val code = resp.status.value
            if (code !in 200..399) {
                issues.add(
                    Issue(
                        type = "ENDPOINT_ERROR_STATUS",
                        severity = if (code >= 500) Severity.HIGH else Severity.LOW,
                        description = "$method $url вернул HTTP $code",
                        path = url,
                        method = method
                    )
                )
            }

            val body = resp.bodyAsText()
            if (containsSensitiveField(body)) {
                issues.add(
                    Issue(
                        type = "EXCESSIVE_DATA_EXPOSURE",
                        severity = Severity.HIGH,
                        description = "Ответ содержит чувствительные поля",
                        path = url,
                        method = method
                    )
                )
            }

            if (enableFuzzing) {
                fuzzer.consentId = consentId
                fuzzer.fuzzEndpoint(
                    url = url,
                    method = methodFromString(method),
                    issues = issues
                )
            }

        } catch (e: Exception) {
            issues.add(
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
}
