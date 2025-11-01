package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.service.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class BuiltinCheckersPlugin(
    private val clientProvider: ClientProvider,
    private val authService: AuthService
) : CheckerPlugin {

    override val name: String = "BuiltinCheckers"

    override suspend fun runCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        fun methodFromString(m: String): HttpMethod = when (m.uppercase()) {
            "GET" -> HttpMethod.Get
            "POST" -> HttpMethod.Post
            "PUT" -> HttpMethod.Put
            "DELETE" -> HttpMethod.Delete
            "PATCH" -> HttpMethod.Patch
            "HEAD" -> HttpMethod.Head
            "OPTIONS" -> HttpMethod.Options
            else -> HttpMethod.Get
        }

        // === GET / HEAD ===
        if (method.equals("GET", true) || method.equals("HEAD", true)) {
            try {
                val resp = authService.performRequestWithAuth(HttpMethod.Get, url, "", "", null, issues)
                val code = resp?.status?.value ?: 0
                val body = safeBodyText(resp)

                if (code !in 200..399) {
                    addIfNotDuplicate(issues, Issue("ENDPOINT_ERROR_STATUS", url, method, if (code >= 500) "HIGH" else "LOW", "Эндпоинт вернул HTTP $code", "HTTP $code"))
                } else {
                    operation.responses?.get("200")?.content?.get("application/json")?.schema?.let { schema ->
                        val validator = ContractValidatorService(null)
                        validator.validateResponse(url, method, code, body).forEach { addIfNotDuplicate(issues, it) }
                    }

                    if (Regex("/\\d+").containsMatchIn(url) || url.endsWith("/1")) {
                        addIfNotDuplicate(issues, Issue("BOLA", url, method, "MEDIUM", "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA", "HTTP $code"))
                    }

                    if (containsSensitiveField(body)) {
                        addIfNotDuplicate(issues, Issue("EXCESSIVE_DATA_EXPOSURE", url, method, "HIGH", "Ответ содержит возможные чувствительные поля", body.take(1000)))
                    }
                }

                checkIDOR(url, method, issues, "", "")
                val requiresAuth = (operation.security != null && operation.security.isNotEmpty()) || (operation.responses?.keys?.contains("401") == true)
                if (requiresAuth) checkBrokenAuth(clientProvider.client, url, method, issues)

            } catch (e: Exception) {
                addNetworkIssue(issues, url, method, "Ошибка сети при GET/HEAD", e.message ?: "unknown")
            }
        }

        // === POST / PUT / PATCH ===
        if (method.equals("POST", true) || method.equals("PUT", true) || method.equals("PATCH", true)) {
            val sampleBodies = mutableListOf<String>()
            try {
                operation.requestBody?.content?.get("application/json")?.schema?.let { schema ->
                    sampleBodies += buildSampleJsonFromSchema(schema)
                }
            } catch (_: Exception) {}

            sampleBodies += """{"__scanner_probe":true,"role":"admin","isAdmin":true}"""
            sampleBodies += generateFuzzPayloads().take(6).toList()
            if (sampleBodies.isEmpty()) sampleBodies += """{"test":"scanner"}"""

            for (body in sampleBodies) {
                try {
                    val resp = authService.performRequestWithAuth(methodFromString(method), url, "", "", {
                        contentType(ContentType.Application.Json)
                        setBody(body)
                        header("X-Scanner-Probe", "true")
                    }, issues)

                    val code = resp?.status?.value ?: 0
                    val respBody = safeBodyText(resp)

                    if ((method.equals("POST", true) || method.equals("PUT", true)) && code in 200..299) {
                        if (!respBody.contains("error", true) && !respBody.contains("validation", true) &&
                            (body.contains("isAdmin") || body.contains("role"))
                        ) {
                            addIfNotDuplicate(issues, Issue("MASS_ASSIGNMENT", url, method, "MEDIUM", "POST/PUT принял дополнительные/административные поля", "HTTP $code, body: ${respBody.take(500)}"))
                        }
                    }

                    operation.requestBody?.content?.get("application/json")?.schema?.let { schema ->
                        val validator = ContractValidatorService(null)
                        validator.validateResponse(url, method, code, body).forEach { addIfNotDuplicate(issues, it) }
                    }

                    if (respBody.contains("Exception", true) || respBody.contains("StackTrace", true) || respBody.contains("java.lang", true)) {
                        addIfNotDuplicate(issues, Issue("INSUFFICIENT_LOGGING", url, method, "MEDIUM", "Сервер возвращает подробные ошибки/стек-трейс", respBody.take(1000)))
                    }

                    if ((body.contains("' OR '1'='1") || body.contains("<script") || body.contains("..\\")) &&
                        (respBody.contains("syntax", true) || respBody.contains("sql", true) || respBody.contains("exception", true))
                    ) {
                        addIfNotDuplicate(issues, Issue("INJECTION", url, method, "HIGH", "Потенциальная инъекция при передаче тела", respBody.take(1000)))
                    }

                } catch (e: Exception) {
                    addNetworkIssue(issues, url, method, "Ошибка сети при POST/PUT/PATCH probe", e.message ?: "unknown")
                }
            }
        }

        // === Admin / Debug / Config endpoints ===
        val adminCandidates = listOf("/admin", "/debug", "/config", "/test", "/internal")
        for (suf in adminCandidates) {
            try {
                val adminUrl = url.trimEnd('/') + suf
                val resp = authService.performRequestWithAuth(HttpMethod.Get, adminUrl, "", "", null, issues)
                if (resp?.status?.value in 200..299) {
                    addIfNotDuplicate(issues, Issue("BROKEN_FUNCTION_LEVEL_AUTH", adminUrl, "GET", "HIGH", "Административный/debug эндпоинт доступен публично", "HTTP ${resp?.status?.value}"))
                }
            } catch (_: Exception) {}
        }

        // Quick injection via query param
        try {
            val injUrl = if (url.contains("?")) "$url&__scan_inj=' OR '1'='1" else "$url?__scan_inj=' OR '1'='1"
            val resp = authService.performRequestWithAuth(HttpMethod.Get, injUrl, "", "", null, issues)
            if (resp?.status?.value in 200..299) {
                val b = safeBodyText(resp)
                if (b.contains("sql", true) || b.contains("syntax", true) || b.contains("exception", true)) {
                    addIfNotDuplicate(issues, Issue("INJECTION", injUrl, "GET", "HIGH", "Потенциальная инъекция через query param", b.take(1000)))
                }
            }
        } catch (_: Exception) {}
    }
}
