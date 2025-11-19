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

        println("=== DebugEndpoints Check ===")
        println("Request URL: ${ctx.url}")
        println("Query Params: ${ctx.url.substringAfter("?", "").takeIf { it.isNotBlank() } ?: "нет"}")
        println("Request Headers: ${ctx.headers}")
        println("Request Body: ${ctx.body ?: "пусто"}")

        // Пробуем выполнить запрос
        val response: HttpResponse? = try {
            consentService.executeContext(ctx)
        } catch (e: Exception) {
            println("Ошибка запроса: ${e.message}")
            null
        }

        response?.let {
            println("Response Status: ${it.status.value}")
            println("Response Headers: ${it.headers.entries().joinToString()}")
            val respBody = runCatching { it.bodyAsText() }.getOrElse { "не удалось прочитать тело" }
            println("Response Body: $respBody")

            if (it.status.value in 200..299) {
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
}
