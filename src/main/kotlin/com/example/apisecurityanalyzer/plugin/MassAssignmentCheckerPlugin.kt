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

class MassAssignmentCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput
) : CheckerPlugin {

    override val name: String = "MassAssignment"

    private val dangerousFieldsPayload = """{"role":"admin","balance":9999999}"""

    override suspend fun runCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        if (!method.equals("POST", true) && !method.equals("PUT", true)) return

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
                contentType(ContentType.Application.Json)
                setBody(dangerousFieldsPayload)
                consentId?.let {
                    val headerName = if (url.contains("/product-agreements")) "X-Product-Agreement-Consent-Id" else "X-Consent-Id"
                    header(headerName, it)
                }
                header("X-Requesting-Bank", userInput.clientId)
            }

            if (response.status.value in 200..299) {
                issues += Issue(
                    type = "MASS_ASSIGNMENT",
                    severity = Severity.HIGH,
                    description = "Сервер принял неизвестные опасные поля",
                    url = url,
                    method = method
                )
            }
        } catch (_: Exception) {
            // Игнорируем ошибки сети
        }
    }
}
