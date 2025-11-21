package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import com.example.apianalyzer.service.FuzzerService
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class BOLACheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val fuzzerService: FuzzerService,
    private val userInput: UserInput,
    private val bankToken: String,
    private val consentId: String
) : CheckerPlugin {

    override val name: String = "UnifiedAttackChecker"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val httpMethod = convertToHttpMethod(method)

        if (userInput.enableBOLA) runBola(url, httpMethod, operation, issues)
        if (userInput.enableIDOR) runIDOR(url, method, operation, issues)
        if (userInput.enableInjection) runInjection(url, method, operation, issues)
        if (userInput.enableMassAssignment) runMassAssignment(url, method, operation, issues)
        if (userInput.enableSensitiveFiles) runExcessiveExposure(url, method, operation, issues)
        if (userInput.enableBrokenAuth) runBrokenAuth(url, method, operation, issues)
        if (userInput.enableRateLimiting) runRateLimit(url, method, operation, issues)
        runDebugExposure(url, method, operation, issues)
        runRoleTampering(url, method, operation, issues)
    }

    private fun convertToHttpMethod(method: String): HttpMethod =
        when (method.uppercase()) {
            "GET" -> HttpMethod.Get
            "POST" -> HttpMethod.Post
            "PUT" -> HttpMethod.Put
            "DELETE" -> HttpMethod.Delete
            "PATCH" -> HttpMethod.Patch
            "OPTIONS" -> HttpMethod.Options
            else -> HttpMethod.Get
        }

    // ---------------------- BOLA ----------------------
    private suspend fun runBola(
        url: String,
        httpMethod: HttpMethod,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val cleanCtx = consentService.buildRequestContext(
            fullUrl = url,
            method = httpMethod.value,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = consentId
        )

        val bolaCtx = cleanCtx.copy(
            headers = cleanCtx.headers.toMutableMap().apply {
                remove("X-Consent-Id")
                remove("X-Product-Agreement-Consent-Id")
                remove("X-Account-Consent-Id")
            }
        )

        val response: HttpResponse? = consentService.executeContext(bolaCtx)
        if (response != null && response.status.value in 200..299) {
            issues.add(
                Issue(
                    type = "BOLA",
                    severity = Severity.HIGH,
                    description = "Доступ к ресурсу возможен без действительного consent.",
                    url = url,
                    method = httpMethod.value,
                    evidence = null,
                    recommendation = "Проверять принадлежность ресурса пользователю и обязательность consent."
                )
            )
        }

        if (userInput.enableFuzzing) {
            try {
                fuzzerService.runFuzzingPublic(
                    url = url,
                    operation = operation,
                    httpMethod = httpMethod,
                    clientId = userInput.clientId,
                    clientSecret = userInput.clientSecret,
                    consentId = consentId,
                    issues = issues
                )
            } catch (ex: Exception) {
                val msg = ex.message?.lowercase() ?: ""
                if (
                    "требуется токен" !in msg &&
                    "token required" !in msg &&
                    "consent" !in msg
                ) {
                    issues.add(
                        Issue(
                            type = "FUZZ_EXCEPTION",
                            severity = Severity.HIGH,
                            description = "Exception during fuzzing: ${ex.message}",
                            url = url,
                            method = httpMethod.value,
                            evidence = null,
                            recommendation = null
                        )
                    )
                }
            }
        }
    }

    // ---------------------- IDOR ----------------------
    private fun runIDOR(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val idPattern = Regex("/\\d+(/|$)")
        if (idPattern.containsMatchIn(url)) {
            issues.add(
                Issue(
                    type = "IDOR",
                    severity = Severity.LOW,
                    description = "Эндпоинт содержит числовой идентификатор (ID), возможна манипуляция ID.",
                    url = url,
                    method = method,
                    evidence = "Обнаружен path-параметр вида /123/",
                    recommendation = "Проверять владельца ресурса по токену/consent."
                )
            )
        }
    }

    // ---------------------- Injection ----------------------
    private suspend fun runInjection(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val payloads = listOf(
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE users; --",
            "{ \"break\": \"json\", \"x\":1 }",
            "`rm -rf /`"
        )

        for (payload in payloads) {
            val ctx = consentService.buildRequestContext(
                fullUrl = url,
                method = method,
                operation = operation,
                userInput = userInput,
                bankToken = bankToken,
                consentId = consentId
            ).copy(body = payload)

            val resp = consentService.executeContext(ctx)
            val code = resp?.status?.value ?: continue
            val bodyText = runCatching { resp.bodyAsText() }.getOrNull() ?: ""

            if (code >= 500 || "error" in bodyText.lowercase()) {
                issues.add(
                    Issue(
                        type = "Injection",
                        severity = Severity.MEDIUM,
                        description = "Возможна инъекция: сервер дал ошибку на payload.",
                        url = url,
                        method = method,
                        evidence = "Payload: $payload\nResponse: $code $bodyText",
                        recommendation = "Внедрить строгую валидацию и экранирование данных."
                    )
                )
            }
        }
    }

    // ---------------------- Mass Assignment ----------------------
    private suspend fun runMassAssignment(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val maliciousBody = """
            {
              "isAdmin": true,
              "role": "superuser",
              "balance": 999999999
            }
        """.trimIndent()

        val ctx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = consentId
        ).copy(body = maliciousBody)

        val resp: HttpResponse? = consentService.executeContext(ctx)
        val body = resp?.let { runCatching { it.bodyAsText() }.getOrNull() } ?: ""

        if ("isAdmin" in body.lowercase() || "superuser" in body.lowercase() || "role" in body.lowercase()) {
            issues.add(
                Issue(
                    type = "MassAssignment",
                    severity = Severity.HIGH,
                    description = "Сервер принял нежелательные поля.",
                    url = url,
                    method = method,
                    evidence = body,
                    recommendation = "Использовать whitelist полей на уровне DTO."
                )
            )
        }
    }

    // ---------------------- Excessive Data Exposure ----------------------
    private suspend fun runExcessiveExposure(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val ctx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = consentId
        )

        val resp = consentService.executeContext(ctx)
        val body = resp?.let { runCatching { it.bodyAsText() }.getOrNull() } ?: ""

        val leakIndicators = listOf("password", "secret", "token", "ssn", "private", "credit", "pin")
        val leaks = leakIndicators.filter { body.contains(it, ignoreCase = true) }

        if (leaks.isNotEmpty()) {
            issues.add(
                Issue(
                    type = "DataExposure",
                    severity = Severity.HIGH,
                    description = "Ответ содержит конфиденциальные данные: ${leaks.joinToString()}.",
                    url = url,
                    method = method,
                    evidence = body,
                    recommendation = "Удалить чувствительные поля или маскировать их."
                )
            )
        }
    }

    // ---------------------- Role Tampering ----------------------
    private suspend fun runRoleTampering(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val baseCtx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = consentId
        )

        val ctx = baseCtx.copy(headers = baseCtx.headers.toMutableMap().apply {
            this["X-User-Role"] = "admin"
        })

        val resp = consentService.executeContext(ctx)
        if (resp?.status?.value in 200..299) {
            issues.add(
                Issue(
                    type = "RoleTampering",
                    severity = Severity.MEDIUM,
                    description = "Переподмена роли через заголовок разрешена.",
                    url = url,
                    method = method,
                    evidence = "X-User-Role=admin",
                    recommendation = "Не доверять заголовкам, проверять роль пользователя на сервере."
                )
            )
        }
    }

    // ---------------------- Broken Auth ----------------------
    private suspend fun runBrokenAuth(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val badTokens = listOf("", "fake123", "Bearer WRONG_TOKEN")

        for (t in badTokens) {
            val ctx = consentService.buildRequestContext(
                fullUrl = url,
                method = method,
                operation = operation,
                userInput = userInput,
                bankToken = t,
                consentId = consentId
            )

            val resp = consentService.executeContext(ctx)
            val code = resp?.status?.value ?: continue

            if (code in 200..299) {
                issues.add(
                    Issue(
                        type = "BrokenAuth",
                        severity = Severity.HIGH,
                        description = "Эндпоинт принимает некорректный или пустой токен.",
                        url = url,
                        method = method,
                        evidence = "Token=\"$t\"",
                        recommendation = "Валидация токена должна блокировать такие запросы."
                    )
                )
            }
        }
    }

    // ---------------------- Rate Limit Test ----------------------
    private suspend fun runRateLimit(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val ctx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = consentId
        )

        var ok = 0
        var tooMany = 0

        repeat(5) {
            val resp = consentService.executeContext(ctx)
            val code = resp?.status?.value ?: return@repeat
            if (code == 429) tooMany++
            if (code in 200..299) ok++
        }

        if (tooMany == 0 && ok >= 5) {
            issues.add(
                Issue(
                    type = "RateLimit",
                    severity = Severity.LOW,
                    description = "Нет заметных признаков rate limiting.",
                    url = url,
                    method = method,
                    recommendation = "Добавить ограничения на количество запросов."
                )
            )
        }
    }

    // ---------------------- Debug Exposure ----------------------
    private fun runDebugExposure(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        if ("debug" in url.lowercase() || "internal" in url.lowercase()) {
            issues.add(
                Issue(
                    type = "DebugEndpoint",
                    severity = Severity.MEDIUM,
                    description = "Обнаружен debug/internal endpoint.",
                    url = url,
                    method = method,
                    recommendation = "Закрыть публичный доступ к debug/internal endpoint."
                )
            )
        }
    }
}
