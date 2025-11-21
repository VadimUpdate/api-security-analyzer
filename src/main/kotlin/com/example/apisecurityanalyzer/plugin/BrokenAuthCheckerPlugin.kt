package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.Operation
import io.swagger.v3.oas.models.media.*

class BrokenAuthCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    private val mapper = jacksonObjectMapper()
    override val name: String = "BrokenAuth"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val requestBody = buildRequestBody(operation)

        val cleanCtx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = null
        )

        val jsonBody = requestBody?.let { mapper.writeValueAsString(it) }
        val cleanCtxWithBody = cleanCtx.copy(body = jsonBody)

        val attackVariants = listOf<Map<String, String>>(
            emptyMap(),
            mapOf("Authorization" to ""),
            mapOf("Authorization" to "Bearer invalidtoken"),
            mapOf("Authorization" to "Bearer ${bankToken.take(5)}broken"),
            mapOf("Auth" to "123"),
            mapOf("X-Auth" to "test"),
            mapOf("Authorization" to "Basic abcdef==")
        )

        for (variant in attackVariants) {
            val badCtx = cleanCtxWithBody.copy(headers = cleanCtxWithBody.headers.toMutableMap())
            badCtx.headers.remove("Authorization")
            badCtx.headers.remove("X-Consent-Id")
            badCtx.headers.putAll(variant)

            val response: HttpResponse? = consentService.executeContext(badCtx)
            response?.let {
                val status = it.status.value
                val respBody = runCatching { it.bodyAsText() }.getOrElse { "не удалось прочитать тело" }

                if (status in 200..299) {
                    issues.add(
                        Issue(
                            type = "BROKEN_AUTH",
                            severity = Severity.HIGH,
                            description = "Эндпоинт успешен без валидной авторизации",
                            url = url,
                            method = method,
                            evidence = "Вариант атаки: ${variant.entries.joinToString()} | Response: $respBody"
                        )
                    )
                }
            }
        }
    }

    private fun buildRequestBody(operation: Operation): Any? {
        val schema = operation.requestBody?.content?.get("application/json")?.schema
        return schema?.let { buildObjectFromSchema(it) }
    }

    private fun buildObjectFromSchema(schema: Schema<*>): Any {
        return when (schema) {
            is ObjectSchema -> {
                val map = mutableMapOf<String, Any>()
                schema.properties?.forEach { (key, propSchema) ->
                    map[key] = buildObjectFromSchema(propSchema)
                }
                map
            }
            is ArraySchema -> listOf(buildObjectFromSchema(schema.items))
            is StringSchema -> "test"
            is NumberSchema -> 0
            is IntegerSchema -> 0
            is BooleanSchema -> false
            else -> emptyMap<String, Any>()
        }
    }
}
