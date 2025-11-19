package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import com.example.apianalyzer.model.UserInput
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class ExcessiveDataExposureCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "ExcessiveDataExposure"

    override suspend fun runCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        val client = clientProvider.client
        val httpMethod = HttpMethod.parse(method)
        val consentId = consentService.selectConsentForPath(
            url.removePrefix(userInput.targetUrl),
            paymentConsentId = null,
            productConsentId = null,
            accountConsentId = null
        )

        try {
            val response: HttpResponse = client.request(url) {
                this.method = httpMethod
                header("Accept", "application/json")
                consentId?.let {
                    val headerName = if (url.contains("/product-agreements")) "X-Product-Agreement-Consent-Id" else "X-Consent-Id"
                    header(headerName, it)
                }
                header("Authorization", "Bearer $bankToken")
                header("X-Requesting-Bank", userInput.clientId)
            }

            val bodyText = runCatching { response.bodyAsText() }.getOrNull()

            if ((bodyText?.length ?: 0) > 1000 || containsSensitiveField(bodyText)) {
                issues += Issue(
                    type = "EXCESSIVE_DATA_EXPOSURE",
                    severity = Severity.MEDIUM,
                    description = "Ответ содержит слишком много или чувствительные данные",
                    url = url,
                    method = method
                )
            }

        } catch (e: Exception) {
            issues += Issue(
                type = "EXCESSIVE_DATA_EXPOSURE_ERROR",
                severity = Severity.LOW,
                description = "Ошибка проверки ExcessiveDataExposure: ${e.message}",
                url = url,
                method = method
            )
        }
    }

    private fun containsSensitiveField(body: String?): Boolean {
        if (body.isNullOrBlank()) return false
        val sensitive = listOf("password", "token", "secret", "ssn", "creditCard", "dob")
        return sensitive.any { body.contains(it, ignoreCase = true) }
    }
}
