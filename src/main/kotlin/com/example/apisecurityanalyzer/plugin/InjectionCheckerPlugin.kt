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

class InjectionCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput
) : CheckerPlugin {

    override val name: String = "Injection"

    override suspend fun runCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        val client = clientProvider.client
        val httpMethod = HttpMethod.parse(method)

        val consentId = consentService.selectConsentForPath(
            url.removePrefix(userInput.targetUrl),
            paymentConsentId = null,
            productConsentId = null,
            accountConsentId = null
        )

        val payloads = listOf("'; DROP TABLE users;--", "\" OR \"1\"=\"1", "<script>alert(1)</script>")

        for (payload in payloads) {
            try {
                val response: HttpResponse = client.request(url) {
                    this.method = httpMethod
                    consentId?.let {
                        val headerName = if (url.contains("/product-agreements")) "X-Product-Agreement-Consent-Id" else "X-Consent-Id"
                        header(headerName, it)
                    }
                    header("X-Requesting-Bank", userInput.clientId)
                    if (httpMethod != HttpMethod.Get) {
                        contentType(ContentType.Application.Json)
                        setBody("""{"test":"$payload"}""")
                    }
                }

                val body = response.bodyAsText()
                if (body.contains("error", true) || response.status.value in 200..299) {
                    issues.add(
                        Issue(
                            type = "INJECTION",
                            severity = Severity.HIGH,
                            description = "Возможная уязвимость инъекции: $payload",
                            url = url,
                            method = method
                        )
                    )
                }
            } catch (_: Exception) {}
        }
    }
}
