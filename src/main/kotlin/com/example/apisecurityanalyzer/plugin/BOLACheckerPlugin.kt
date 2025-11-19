package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation

class BOLACheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "BOLA/IDOR"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val cleanCtx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = null
        )

        println("=== BOLA/IDOR Check ===")
        println("Request URL: ${cleanCtx.url}")
        println("Query Params: ${cleanCtx.url.substringAfter("?", "").takeIf { it.isNotBlank() } ?: "нет"}")
        println("Request Headers: ${cleanCtx.headers}")
        println("Request Body: ${cleanCtx.body ?: "пусто"}")

        val bolaCtx = cleanCtx.copy(headers = cleanCtx.headers.toMutableMap())
        bolaCtx.headers.remove("X-Consent-Id")
        bolaCtx.headers.remove("X-Product-Agreement-Consent-Id")

        val response: HttpResponse? = consentService.executeContext(bolaCtx)
        response?.let {
            println("Response Status: ${it.status.value}")
            println("Response Headers: ${it.headers.entries().joinToString()}")
            val respBody = runCatching { it.bodyAsText() }.getOrElse { "не удалось прочитать тело" }
            println("Response Body: $respBody")

            if (it.status.value in 200..299) {
                issues.add(
                    Issue(
                        type = "BOLA",
                        severity = Severity.HIGH,
                        description = "Эндпоинт доступен без consent-id",
                        url = url,
                        method = method
                    )
                )
            }
        }

        if (url.contains(Regex("/[A-Za-z]*/\\d+"))) {
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
