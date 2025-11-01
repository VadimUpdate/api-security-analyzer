package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.service.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class BuiltinCheckersPlugin(
    private val clientProvider: ClientProvider,
    private val authService: AuthService
) : CheckerPlugin {

    override val name: String = "BuiltinCheckers"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
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

        val httpMethod = methodFromString(method)

        // === GET / HEAD ===
        if (method.equals("GET", true) || method.equals("HEAD", true)) {
            try {
                val resp = authService.performRequestWithAuth(HttpMethod.Get, url, "", "", null, issues)
                val code = resp?.status?.value ?: 0
                val body = safeBodyText(resp)

                if (code !in 200..399) {
                    addIfNotDuplicate(issues, Issue(
                        type = "ENDPOINT_ERROR_STATUS",
                        severity = if (code >= 500) Severity.HIGH else Severity.LOW,
                        description = "Эндпоинт $url вернул HTTP $code"
                    ))
                }

                // BOLA
                if (Regex("/\\d+").containsMatchIn(url) || url.endsWith("/1")) {
                    addIfNotDuplicate(issues, Issue(
                        type = "BOLA",
                        severity = Severity.MEDIUM,
                        description = "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA, HTTP $code"
                    ))
                }

                // Excessive data exposure
                if (containsSensitiveField(body)) {
                    addIfNotDuplicate(issues, Issue(
                        type = "EXCESSIVE_DATA_EXPOSURE",
                        severity = Severity.HIGH,
                        description = "Ответ содержит возможные чувствительные поля, HTTP $code"
                    ))
                }

                // IDOR
                checkIDOR(url, method, issues, "", "")

                // Broken Auth
                val requiresAuth = (operation.security != null && operation.security.isNotEmpty()) ||
                        (operation.responses?.keys?.contains("401") == true)
                if (requiresAuth) checkBrokenAuth(clientProvider.client, url, method, issues)

                // Rate limiting (API4)
                checkRateLimiting(url, httpMethod, issues, authService)

            } catch (e: Exception) {
                addIfNotDuplicate(issues, Issue(
                    type = "NETWORK_ERROR",
                    severity = Severity.MEDIUM,
                    description = "Ошибка сети при GET/HEAD $url: ${e.message ?: "unknown"}"
                ))
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
                    val resp = authService.performRequestWithAuth(httpMethod, url, "", "", {
                        contentType(ContentType.Application.Json)
                        setBody(body)
                        header("X-Scanner-Probe", "true")
                    }, issues)

                    val code = resp?.status?.value ?: 0
                    val respBody = safeBodyText(resp)

                    // Mass assignment (API6)
                    if ((method.equals("POST", true) || method.equals("PUT", true)) && code in 200..299) {
                        if (!respBody.contains("error", true) && !respBody.contains("validation", true) &&
                            (body.contains("isAdmin") || body.contains("role"))
                        ) {
                            addIfNotDuplicate(issues, Issue(
                                type = "MASS_ASSIGNMENT",
                                severity = Severity.MEDIUM,
                                description = "POST/PUT принял дополнительные/административные поля, HTTP $code, body: ${respBody.take(500)}"
                            ))
                        }
                    }

                    // Insufficient logging (API10)
                    if (respBody.contains("Exception", true) || respBody.contains("StackTrace", true) || respBody.contains("java.lang", true)) {
                        addIfNotDuplicate(issues, Issue(
                            type = "INSUFFICIENT_LOGGING",
                            severity = Severity.MEDIUM,
                            description = "Сервер возвращает подробные ошибки/стек-трейс, HTTP $code"
                        ))
                    }

                    // Injection (API8)
                    if ((body.contains("' OR '1'='1") || body.contains("<script") || body.contains("..\\")) &&
                        (respBody.contains("syntax", true) || respBody.contains("sql", true) || respBody.contains("exception", true))
                    ) {
                        addIfNotDuplicate(issues, Issue(
                            type = "INJECTION",
                            severity = Severity.HIGH,
                            description = "Потенциальная инъекция при передаче тела, HTTP $code"
                        ))
                    }

                } catch (e: Exception) {
                    addIfNotDuplicate(issues, Issue(
                        type = "NETWORK_ERROR",
                        severity = Severity.MEDIUM,
                        description = "Ошибка сети при POST/PUT/PATCH $url: ${e.message ?: "unknown"}"
                    ))
                }
            }

            // Rate limiting (API4)
            checkRateLimiting(url, httpMethod, issues, authService)
        }

        // === Admin / Debug / Config endpoints (API5) ===
        val adminCandidates = listOf("/admin", "/debug", "/config", "/test", "/internal")
        for (suf in adminCandidates) {
            try {
                val adminUrl = url.trimEnd('/') + suf
                val resp = authService.performRequestWithAuth(HttpMethod.Get, adminUrl, "", "", null, issues)
                if (resp?.status?.value in 200..299) {
                    addIfNotDuplicate(issues, Issue(
                        type = "BROKEN_FUNCTION_LEVEL_AUTH",
                        severity = Severity.HIGH,
                        description = "Административный/debug эндпоинт доступен публично: $adminUrl"
                    ))
                }
            } catch (_: Exception) {}
        }

        // === Quick injection via query param (API8) ===
        try {
            val injUrl = if (url.contains("?")) "$url&__scan_inj=' OR '1'='1" else "$url?__scan_inj=' OR '1'='1"
            val resp = authService.performRequestWithAuth(HttpMethod.Get, injUrl, "", "", null, issues)
            if (resp?.status?.value in 200..299) {
                val b = safeBodyText(resp)
                if (b.contains("sql", true) || b.contains("syntax", true) || b.contains("exception", true)) {
                    addIfNotDuplicate(issues, Issue(
                        type = "INJECTION",
                        severity = Severity.HIGH,
                        description = "Потенциальная инъекция через query param: $injUrl"
                    ))
                }
            }
        } catch (_: Exception) {}

        // === Security Misconfiguration (API7) ===
        val docsPaths = listOf("/swagger", "/swagger-ui", "/docs", "/redoc")
        for (docPath in docsPaths) {
            try {
                val docUrl = url.trimEnd('/') + docPath
                val resp = authService.performRequestWithAuth(HttpMethod.Get, docUrl, "", "", null, issues)
                if (resp?.status?.value in 200..299) {
                    addIfNotDuplicate(issues, Issue(
                        type = "SECURITY_MISCONFIGURATION",
                        severity = Severity.MEDIUM,
                        description = "Публичный доступ к документации API: $docUrl"
                    ))
                }
            } catch (_: Exception) {}
        }

        // === Improper Assets Management (API9) ===
        val legacyCandidates = listOf("/v0", "/v1", "/old", "/sandbox", "/mock", "/backup", "/config.json")
        for (suf in legacyCandidates) {
            try {
                val legacyUrl = url.trimEnd('/') + suf
                val resp = authService.performRequestWithAuth(HttpMethod.Get, legacyUrl, "", "", null, issues)
                if (resp?.status?.value in 200..299) {
                    addIfNotDuplicate(issues, Issue(
                        type = "IMPROPER_ASSETS_MANAGEMENT",
                        severity = Severity.MEDIUM,
                        description = "Публично доступный устаревший/test/debug ресурс: $legacyUrl"
                    ))
                }
            } catch (_: Exception) {}
        }
    }

    // === Rate Limiting helper (API4) ===
    private suspend fun checkRateLimiting(url: String, method: HttpMethod, issues: MutableList<Issue>, authService: AuthService) {
        try {
            var triggered = false
            repeat(5) { // 5 быстрых запросов подряд
                val resp = authService.performRequestWithAuth(method, url, "", "", null, issues)
                if (resp?.status?.value == 429) triggered = true
            }
            if (!triggered) {
                addIfNotDuplicate(issues, Issue(
                    type = "RATE_LIMITING",
                    severity = Severity.MEDIUM,
                    description = "Эндпоинт $url не защищен rate limiting (можно слать много запросов)"
                ))
            }
        } catch (_: Exception) {}
    }
}
