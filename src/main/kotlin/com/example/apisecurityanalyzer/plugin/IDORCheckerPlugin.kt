package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation

class IDORCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "IDOR"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        // Проверка URL на прямые идентификаторы
        if (!url.matches(Regex(".*/\\d+.*"))) return

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

        response?.let {
            if (it.status.value in 200..299) {
                issues.add(
                    Issue(
                        type = "IDOR",
                        severity = Severity.MEDIUM,
                        description = "URL содержит прямой объектный идентификатор, возможен IDOR",
                        url = url,
                        method = method
                    )
                )
            }
        }
    }
}
