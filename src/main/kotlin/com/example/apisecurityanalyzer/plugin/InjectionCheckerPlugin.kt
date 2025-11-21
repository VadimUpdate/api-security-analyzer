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

    private val payloads = mapOf(
        "SQL" to listOf(
            "'; DROP TABLE users;--",
            "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--"
        ),
        "XSS" to listOf(
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><svg/onload=alert(1)>"
        ),
        "Command" to listOf(
            "`ls`",
            "$(reboot)",
            "|| whoami"
        )
    )

    private fun recommendationForCategory(category: String) = when (category) {
        "SQL" -> "Используйте подготовленные выражения (prepared statements) и экранируйте входные данные."
        "XSS" -> "Экранируйте данные, выводимые в HTML, и используйте Content Security Policy (CSP)."
        "Command" -> "Не формируйте системные команды с пользовательского ввода; используйте безопасные API."
        else -> "Проверьте вводимые данные на корректность и экранируйте специальные символы."
    }

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        for ((category, payloadList) in payloads) {
            for (payload in payloadList) {
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

                val bodyText = runCatching { response?.bodyAsText() }.getOrNull()?.lowercase()
                val status = response?.status?.value ?: 0

                val detected = when {
                    bodyText == null -> false
                    category == "SQL" && (status in 500..599 || bodyText.contains("error") || bodyText.contains("exception")) -> true
                    category == "XSS" && bodyText.contains("<script") -> true
                    category == "Command" && (status in 500..599 || bodyText.contains("command")) -> true
                    else -> false
                }


                if (detected) {
                    issues.add(
                        Issue(
                            type = "INJECTION",
                            severity = Severity.HIGH,
                            description = "Возможная $category инъекция обнаружена с payload: \"$payload\".\n" +
                                    "Рекомендация: ${recommendationForCategory(category)}",
                            url = url,
                            method = method
                        )
                    )
                }
            }
        }
    }
}
