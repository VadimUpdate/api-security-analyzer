package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import com.example.apianalyzer.service.FuzzerService
import io.ktor.client.statement.*
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
        runBola(url, method, operation, issues)
        runIDOR(url, method, operation, issues)
        runInjection(url, method, operation, issues)
        runMassAssignment(url, method, operation, issues)
        runExcessiveExposure(url, method, operation, issues)
        runRoleTampering(url, method, operation, issues)
        runBrokenAuth(url, method, operation, issues)
        runRateLimit(url, method, operation, issues)
        runDebugExposure(url, method, operation, issues)
    }

    private suspend fun runBola(
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
            consentId = consentId
        )

        val bolaCtx = cleanCtx.copy(headers = cleanCtx.headers.toMutableMap().apply {
            remove("X-Consent-Id")
            remove("X-Product-Agreement-Consent-Id")
        })

        val response: HttpResponse? = consentService.executeContext(bolaCtx)
        response?.let {
            val code = it.status.value
            if (code in 200..299) {
                issues.add(
                    Issue(
                        type = "BOLA",
                        severity = Severity.HIGH,
                        description = "Доступ к ресурсу возможен без согласия пользователя (consent).",
                        url = url,
                        method = method,
                        evidence = "HTTP $code. Рекомендуется проверять владельца ресурса на сервере и блокировать запрос без соответствующего consent."
                    )
                )
            }
        }

        if (userInput.enableFuzzing) {
            fuzzerService.runFuzzing(
                url = url,
                operation = operation,
                clientId = userInput.clientId,
                clientSecret = userInput.clientSecret,
                consentId = consentId,
                issues = issues
            )
        }
    }

    private fun runIDOR(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val idPattern = Regex("/[A-Za-z-_]*/\\d+(/|$)")
        if (url.contains(idPattern)) {
            issues.add(
                Issue(
                    type = "IDOR",
                    severity = Severity.LOW,
                    description = "Обнаружен числовой идентификатор ресурса. Возможна манипуляция ID для доступа к чужим данным.",
                    url = url,
                    method = method,
                    evidence = "Проверить, может ли другой пользователь получить данные по этому ID.",
                    recommendation = "Добавить проверку владельца ресурса на сервере, не доверять ID из запроса."
                )
            )
        }
    }

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
            "{\"break\":\"json\", \"x\": 1}",
            "`shutdown now`"
        )

        for (p in payloads) {
            val ctx = consentService.buildRequestContext(
                fullUrl = url,
                method = method,
                operation = operation,
                userInput = userInput,
                bankToken = bankToken,
                consentId = consentId
            ).copy(body = p)

            val resp = consentService.executeContext(ctx)
            resp?.let {
                val code = it.status.value
                val body = runCatching { it.bodyAsText() }.getOrElse { "" }
                if (code >= 500 || body.contains("error", true)) {
                    issues.add(
                        Issue(
                            type = "Injection",
                            severity = Severity.MEDIUM,
                            description = "Сервер реагирует ошибками на инъекционные payload'ы, возможна уязвимость к SQL/JSON/Command инъекциям.",
                            url = url,
                            method = method,
                            evidence = "Payload: $p, Response: $code/$body",
                            recommendation = "Использовать подготовленные выражения, валидацию и экранирование входных данных."
                        )
                    )
                }
            }
        }
    }

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

        val resp = consentService.executeContext(ctx)
        resp?.let {
            val body = runCatching { it.bodyAsText() }.getOrElse { "" }
            if (body.contains("superuser", true) || body.contains("isAdmin", true) || body.contains("role", true)) {
                issues.add(
                    Issue(
                        type = "MassAssignment",
                        severity = Severity.HIGH,
                        description = "Сервер принимает неожиданные поля в теле запроса.",
                        url = url,
                        method = method,
                        evidence = "Ответ содержит поля: $body",
                        recommendation = "Использовать whitelist полей для обновления, фильтровать входящие данные."
                    )
                )
            }
        }
    }

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
        val body = resp?.let { runCatching { it.bodyAsText() }.getOrElse { "" } } ?: ""

        val leakIndicators = listOf("password", "secret", "token", "ssn", "private", "credit", "pin")
        val leaks = leakIndicators.filter { body.contains(it, true) }
        if (leaks.isNotEmpty()) {
            issues.add(
                Issue(
                    type = "DataExposure",
                    severity = Severity.HIGH,
                    description = "Ответ содержит потенциально чувствительные данные: ${leaks.joinToString(", ")}.",
                    url = url,
                    method = method,
                    evidence = body,
                    recommendation = "Маскировать PII, использовать DTO без конфиденциальных полей."
                )
            )
        }
    }

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
            put("X-User-Role", "admin")
        })

        val resp = consentService.executeContext(ctx)
        resp?.let {
            if (it.status.value in 200..299) {
                issues.add(
                    Issue(
                        type = "RoleTampering",
                        severity = Severity.MEDIUM,
                        description = "Смена роли через header не заблокирована.",
                        url = url,
                        method = method,
                        evidence = "X-User-Role=admin",
                        recommendation = "Проверять роль пользователя на сервере, не доверять заголовкам."
                    )
                )
            }
        }
    }


    private suspend fun runBrokenAuth(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        val badTokens = listOf("", "fake123", "Bearer WRONGTOKEN999")

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
            resp?.let {
                if (it.status.value in 200..299) {
                    issues.add(
                        Issue(
                            type = "BrokenAuth",
                            severity = Severity.HIGH,
                            description = "Эндпоинт принимает неверный или пустой токен.",
                            url = url,
                            method = method,
                            evidence = "Token=$t",
                            recommendation = "Инвалидировать неправильные токены, использовать короткий TTL и refresh tokens."
                        )
                    )
                }
            }
        }
    }

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

        var okCount = 0
        var tooMany = 0

        repeat(5) {
            val resp = consentService.executeContext(ctx)
            val code = resp?.status?.value ?: -1
            if (code == 429) tooMany++
            if (code in 200..299) okCount++
        }

        if (tooMany == 0 && okCount >= 5) {
            issues.add(
                Issue(
                    type = "RateLimit",
                    severity = Severity.LOW,
                    description = "Нет видимых признаков rate limiting.",
                    url = url,
                    method = method,
                    recommendation = "Рассмотреть введение ограничений на количество запросов с одного пользователя/IP."
                )
            )
        }
    }

    private fun runDebugExposure(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        if (url.contains("debug", true) || url.contains("internal", true)) {
            issues.add(
                Issue(
                    type = "DebugEndpoint",
                    severity = Severity.MEDIUM,
                    description = "Обнаружен debug/internal endpoint.",
                    url = url,
                    method = method,
                    recommendation = "Отключить публичный доступ к debug/internal endpoint, ограничить доступ через firewall или VPN."
                )
            )
        }
    }
}
