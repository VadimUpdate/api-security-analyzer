package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class BrokenAuthCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput
) : CheckerPlugin {

    override val name: String = "BrokenAuth"

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
                // НЕ добавляем Authorization
                consentId?.let {
                    val headerName = if (url.contains("/product-agreements")) "X-Product-Agreement-Consent-Id" else "X-Consent-Id"
                    header(headerName, it)
                }
                header("X-Requesting-Bank", userInput.clientId)
                if (httpMethod != HttpMethod.Get) {
                    contentType(ContentType.Application.Json)
                    setBody("{}")
                }
            }

            if (response.status.value in 200..299) {
                issues += Issue(
                    type = "BROKEN_AUTH",
                    severity = Severity.HIGH,
                    description = "Эндпоинт доступен без валидного токена",
                    url = url,
                    method = method
                )
            }
        } catch (_: Exception) {
            // Игнорируем ошибки сети
        }
    }
}
