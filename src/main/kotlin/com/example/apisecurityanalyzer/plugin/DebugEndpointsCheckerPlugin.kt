package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation

class DebugEndpointsCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "DebugEndpoints"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        // Строим чистый контекст запроса
        val ctx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = null
        )

        // Пробуем выполнить GET или HEAD запрос
        val response: HttpResponse? = try {
            consentService.executeContext(ctx)
        } catch (_: Exception) {
            null
        }

        // Если эндпоинт доступен и возвращает 2xx → возможно debug/admin
        if (response != null && response.status.value in 200..299) {
            issues.add(
                Issue(
                    type = "DEBUG_ENDPOINT_CHECK",
                    severity = Severity.MEDIUM,
                    description = "Эндпоинт может быть debug/admin, доступен без ограничений",
                    url = url,
                    method = method
                )
            )
        }
    }
}
