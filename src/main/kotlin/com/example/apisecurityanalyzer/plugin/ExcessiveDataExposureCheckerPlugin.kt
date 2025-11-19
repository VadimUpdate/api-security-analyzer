package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation

class ExcessiveDataExposureCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "ExcessiveDataExposure"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        // Формируем чистый RequestContext
        val ctx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = null
        )

        val response: HttpResponse? = try {
            consentService.executeContext(ctx)
        } catch (_: Exception) {
            null
        }

        val bodyText = runCatching { response?.bodyAsText() }.getOrNull()

        if ((bodyText?.length ?: 0) > 1000 || containsSensitiveField(bodyText)) {
            issues.add(
                Issue(
                    type = "EXCESSIVE_DATA_EXPOSURE",
                    severity = Severity.MEDIUM,
                    description = "Ответ содержит слишком много или чувствительные данные",
                    url = url,
                    method = method
                )
            )
        }
    }

    private fun containsSensitiveField(body: String?): Boolean {
        if (body.isNullOrBlank()) return false
        val sensitiveFields = listOf("password", "token", "secret", "ssn", "creditCard", "dob")
        return sensitiveFields.any { body.contains(it, ignoreCase = true) }
    }
}
