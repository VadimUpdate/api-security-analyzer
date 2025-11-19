package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation

class InjectionCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput
) : CheckerPlugin {

    override val name: String = "Injection"

    private val payloads = listOf(
        "'; DROP TABLE users;--",
        "\" OR \"1\"=\"1",
        "<script>alert(1)</script>"
    )

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        for (payload in payloads) {
            val safePayload = payload.replace("\"", "\\\"")
            val ctx = consentService.buildRequestContext(
                fullUrl = url,
                method = method,
                operation = operation,
                userInput = userInput,
                bankToken = "",
                consentId = null
            )

            val attackCtx = if (!method.equals("GET", true)) {
                ctx.copy(body = """{"test":"$safePayload"}""")
            } else ctx

            val response: HttpResponse? = try {
                consentService.executeContext(attackCtx)
            } catch (_: Exception) {
                null
            }

            val bodyText = runCatching { response?.bodyAsText() }.getOrNull()
            if (bodyText?.contains("error", true) == true || response?.status?.value in 200..299) {
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
        }
    }
}
