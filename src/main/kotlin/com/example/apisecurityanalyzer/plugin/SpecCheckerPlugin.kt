package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation

class SpecCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "Spec"

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

        println("=== Spec Check ===")
        println("Request URL: ${ctx.url}")
        println("Request Headers: ${ctx.headers}")
        println("Request Body: ${ctx.body ?: "пусто"}")

        try {
            val response: HttpResponse? = consentService.executeContext(ctx)

            response?.let {
                println("Response Status: ${it.status.value}")
                println("Response Headers: ${it.headers.entries().joinToString()}")
                val respBody = runCatching { it.bodyAsText() }.getOrElse { "не удалось прочитать тело" }
                println("Response Body: $respBody")

                if (it.status.value >= 400) {
                    issues.add(
                        Issue(
                            type = "SPEC_MISMATCH",
                            severity = Severity.MEDIUM,
                            description = "Ответ не соответствует спецификации (HTTP ${it.status.value})",
                            url = url,
                            method = method
                        )
                    )
                }
            } ?: run {
                issues.add(
                    Issue(
                        type = "SPEC_MISMATCH",
                        severity = Severity.MEDIUM,
                        description = "Нет ответа от сервера",
                        url = url,
                        method = method
                    )
                )
            }
        } catch (e: Exception) {
            issues.add(
                Issue(
                    type = "SPEC_CHECK_PLUGIN_ERROR",
                    severity = Severity.LOW,
                    description = "Ошибка SpecChecker: ${e.message}",
                    url = url,
                    method = method
                )
            )
        }
    }
}
