package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.swagger.v3.oas.models.Operation
import io.ktor.client.statement.*
import kotlin.system.measureTimeMillis

class RateLimitingCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String? = null
) : CheckerPlugin {

    override val name: String = "RateLimiting"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val ctx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken ?: "",
            consentId = consentService.selectConsentForPath(
                url.removePrefix(userInput.targetUrl),
                paymentConsentId = null,
                productConsentId = null,
                accountConsentId = null
            )
        )

        println("=== RateLimiting Check ===")
        println("Request URL: ${ctx.url}")
        println("Query Params: ${ctx.url.substringAfter("?", "").takeIf { it.isNotBlank() } ?: "нет"}")
        println("Request Headers: ${ctx.headers}")
        println("Request Body: ${ctx.body ?: "пусто"}")

        var lastResponse: HttpResponse? = null
        val responseTimes = mutableListOf<Long>()
        var successCount = 0

        try {
            repeat(5) { attempt ->
                println("RateLimiting attempt ${attempt + 1}")
                val duration = measureTimeMillis {
                    lastResponse = consentService.executeContext(ctx)
                    if (lastResponse?.status?.value in 200..299) successCount++
                }
                responseTimes.add(duration)
            }
        } catch (e: Exception) {
            val evidence = buildString {
                appendLine("Exception during rate limiting check: ${e.message}")
                val bodyText = lastResponse?.runCatching { bodyAsText() }?.getOrNull() ?: "нет"
                appendLine("Response body (if any): $bodyText")
                appendLine("Response times: $responseTimes ms")
                appendLine("Successful responses: $successCount / 5")
            }


            issues.add(
                Issue(
                    type = "RATE_LIMITING",
                    severity = Severity.MEDIUM,
                    description = "Проблема с rate limiting или нестабильный endpoint",
                    url = url,
                    method = method,
                    evidence = evidence
                )
            )
        }

        // Добавим мелкий отчет, если все прошло успешно, но были подозрительные задержки
        if (successCount == 5 && responseTimes.any { it > 1000 }) {
            issues.add(
                Issue(
                    type = "RATE_LIMITING",
                    severity = Severity.LOW,
                    description = "Эндпоинт стабильно отвечает, но есть задержки > 1 сек",
                    url = url,
                    method = method,
                    evidence = "Response times: $responseTimes ms"
                )
            )
        }
    }
}
