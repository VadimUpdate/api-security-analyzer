package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation

class SpecCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "SpecChecker"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val responseBody = safeRequest(url, method)
        responseBody?.let { body ->
            checkSpecCompliance(url, method, operation, body, issues)
        }
    }

    private suspend fun safeRequest(url: String, method: String): String? {
        return try {
            clientProvider.client.request(url) {
                this.method = io.ktor.http.HttpMethod.parse(method)
            }.bodyAsText()
        } catch (_: Exception) {
            null
        }
    }

    private fun checkSpecCompliance(
        url: String,
        method: String,
        operation: Operation,
        responseBody: String,
        issues: MutableList<Issue>
    ) {
        // Простейшая проверка: отсутствие обязательных полей
        operation.responses?.forEach { (_, resp) ->
            val requiredFields = resp.content?.values?.firstOrNull()?.schema?.required ?: emptyList()
            requiredFields.forEach { field ->
                if (!responseBody.contains(field)) {
                    issues.add(
                        Issue(
                            type = "SPECMATCH",
                            severity = Severity.MEDIUM,
                            description = "Обязательное поле '$field' отсутствует в ответе",
                            url = url,
                            method = method,
                            evidence = responseBody
                        )
                    )
                }
            }
        }

        // TODO: добавить проверку типов и выявление неописанных эндпоинтов
    }
}
