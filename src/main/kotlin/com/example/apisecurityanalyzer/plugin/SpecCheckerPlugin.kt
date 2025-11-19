package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
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

        try {
            val response = consentService.executeContext(ctx)

            if (response == null || response.status.value >= 400) {
                issues.add(
                    Issue(
                        type = "SPEC_MISMATCH",
                        severity = Severity.MEDIUM,
                        description = "Ответ не соответствует спецификации (HTTP ${response?.status?.value ?: "нет ответа"})",
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
