package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.swagger.v3.oas.models.Operation

class RateLimitingCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
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
            bankToken = bankToken,
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

        try {
            repeat(5) {
                consentService.executeContext(ctx)
            }
        } catch (e: Exception) {
            issues.add(
                Issue(
                    type = "RATE_LIMITING",
                    severity = Severity.MEDIUM,
                    description = "Возможная проблема с rate limiting: ${e.message}",
                    url = url,
                    method = method
                )
            )
        }
    }
}
