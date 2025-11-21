package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

class MassAssignmentCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String? = null
) : CheckerPlugin {

    override val name: String = "MassAssignment"

    private val mapper = jacksonObjectMapper()
    private val dangerousFieldsPayload = """{"role":"admin","balance":9999999}"""

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        if (!method.equals("POST", true) && !method.equals("PUT", true)) return

        val ctx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken ?: "",
            consentId = null
        )

        val attackCtx = ctx.copy(body = dangerousFieldsPayload)

        val response: HttpResponse? = try {
            consentService.executeContext(attackCtx)
        } catch (_: Exception) {
            null
        }

        val evidence = runCatching { response?.bodyAsText() }.getOrNull()

        if (response?.status?.value in 200..299) {
            issues.add(
                Issue(
                    type = "MASS_ASSIGNMENT",
                    severity = Severity.HIGH,
                    description = """
                        Сервер принял неизвестные опасные поля в запросе: $dangerousFieldsPayload.
                        Рекомендация: Ограничьте поля, которые клиент может обновлять, используйте белые списки (whitelisting) и валидацию данных.
                    """.trimIndent(),
                    url = url,
                    method = method,
                    evidence = evidence?.take(500) // обрезаем длинные ответы
                )
            )
        }
    }
}
