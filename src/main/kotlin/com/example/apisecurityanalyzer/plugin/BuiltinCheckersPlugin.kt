package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.service.AuthService
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.FuzzerService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class BuiltinCheckersPlugin(
    private val clientProvider: ClientProvider,
    private val authService: AuthService,
    private val bankBaseUrl: String,
    private val clientId: String,
    private val clientSecret: String,
    private val enableFuzzing: Boolean = false,
    private val politenessDelayMs: Long = 150L,
    private val maxConcurrency: Int = 4,
    private val maxPayloadsPerEndpoint: Int = 10
) : CheckerPlugin {

    override val name: String = "BuiltinCheckers"

    var consentId: String? = null
    var bankToken: String? = null
    private val client get() = clientProvider.client

    private val fuzzerService: FuzzerService by lazy {
        FuzzerService(
            authService = authService,
            bankBaseUrl = bankBaseUrl,
            clientId = clientId,
            clientSecret = clientSecret,
            enabled = enableFuzzing,
            politenessDelayMs = politenessDelayMs,
            maxConcurrency = maxConcurrency,
            maxPayloadsPerEndpoint = maxPayloadsPerEndpoint
        ).apply {
            this.consentId = this@BuiltinCheckersPlugin.consentId ?: ""
            this.bankToken = this@BuiltinCheckersPlugin.bankToken ?: ""
        }
    }

    // -----------------------
    // Attack Context
    // -----------------------
    private fun buildAttackContext(url: String, method: String): AttackContext {
        val ctx = AttackContext()
        ctx.headers["Authorization"] = "Bearer ${bankToken ?: ""}"

        val chosenConsent = when {
            url.contains("/payment-consents") -> consentId
            url.contains("/product-agreement-consents") -> consentId
            url.contains("/product-agreements") -> consentId
            url.contains("/cards") -> consentId
            url.contains("/accounts") -> consentId
            else -> consentId
        }

        if (!chosenConsent.isNullOrBlank()) {
            val hname = if (url.contains("/product-agreements")) "X-Product-Agreement-Consent-Id" else "X-Consent-Id"
            ctx.headers[hname] = chosenConsent
        }

        ctx.headers["X-Requesting-Bank"] = clientId

        if (!method.equals("GET", true)) {
            ctx.body = "{}"
        }

        return ctx
    }

    // -----------------------
    // SPEC CHECK
    // -----------------------
    private suspend fun runSpecCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        try {
            val resp: HttpResponse = client.request(url) {
                this.method = methodFromString(method)
                header("Accept", "application/json")
                contentType(ContentType.Application.Json)
            }

            if (resp.status.value !in 200..399) {
                issues.add(
                    Issue(
                        "SPEC_MISMATCH",
                        Severity.LOW,
                        "Спецификация некорректна: HTTP ${resp.status.value}",
                        url,
                        method
                    )
                )
            }

        } catch (e: Exception) {
            issues.add(
                Issue(
                    "SPEC_MISMATCH",
                    Severity.LOW,
                    "Ошибка вызова по спецификации: ${e.message}",
                    url,
                    method
                )
            )
        }
    }

    // -----------------------
    // ATTACK CHECK
    // -----------------------
    private suspend fun runAttackCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        val ctx = buildAttackContext(url, method)

        val resp: HttpResponse = try {
            authService.performRequestWithAuth(
                method = methodFromString(method),
                url = url,
                bankBaseUrl = bankBaseUrl,
                clientId = clientId,
                clientSecret = clientSecret,
                consentId = consentId ?: "",
                addClientIdToGet = false,
                requireToken = true,
                bodyBlock = {
                    ctx.headers.forEach { (k, v) -> header(k, v) }
                    ctx.body?.let { setBody(it) }
                },
                issues = issues
            )
        } catch (ex: Exception) {
            issues.add(
                Issue(
                    "NETWORK_ERROR",
                    Severity.MEDIUM,
                    "Ошибка сети при $method $url: ${ex.message}",
                    url,
                    method
                )
            )
            return
        }

        val code = resp.status.value
        val body = resp.bodyAsText()

        // -----------------------
        // #1 Endpoint errors
        // -----------------------
        if (code !in 200..399) {
            issues.add(
                Issue(
                    "ENDPOINT_ERROR_STATUS",
                    if (code >= 500) Severity.HIGH else Severity.MEDIUM,
                    "$method $url → HTTP $code",
                    url,
                    method
                )
            )
        }

        // -----------------------
        // #2 Sensitive data exposure
        // -----------------------
        if (containsSensitiveField(body)) {
            issues.add(
                Issue(
                    "EXCESSIVE_DATA_EXPOSURE",
                    Severity.HIGH,
                    "Ответ содержит чувствительные данные",
                    url,
                    method
                )
            )
        }

        // -----------------------
        // #3 BOLA + IDOR
        // -----------------------
        if (method.equals("GET", true)) {
            if (Regex("/\\d+").containsMatchIn(url)) {
                issues.add(
                    Issue("BOLA", Severity.MEDIUM, "Возможен BOLA", url, method)
                )
            }
            if (url.contains("user") && url.contains("id", true)) {
                issues.add(
                    Issue("IDOR", Severity.MEDIUM, "Возможный IDOR", url, method)
                )
            }
        }

        // -----------------------
        // #4 Injection
        // -----------------------
        performInjectionTests(url, method, ctx, issues)

        // -----------------------
        // #5 Mass Assignment
        // -----------------------
        performMassAssignment(url, method, ctx, issues)

        // -----------------------
        // #6 Fuzzing
        // -----------------------
        if (enableFuzzing) {
            fuzzerService.bankToken = bankToken ?: ""
            fuzzerService.consentId = consentId ?: ""
            fuzzerService.fuzzEndpoint(url, methodFromString(method), issues)
        }

        // -----------------------
        // #7 Rate Limiting
        // -----------------------
        checkRateLimiting(url, methodFromString(method), issues)

        // -----------------------
        // #8 Broken Auth
        // -----------------------
        if (tokenBroken(url, method, issues)) {
            issues.add(
                Issue(
                    "BROKEN_AUTH",
                    Severity.HIGH,
                    "Эндпоинт доступен без валидного токена",
                    url,
                    method
                )
            )
        }

        // -----------------------
        // #9 Debug endpoints
        // -----------------------
        if (url.contains("/debug") || url.contains("/admin")) {
            issues.add(
                Issue(
                    "DEBUG_ENDPOINT",
                    Severity.MEDIUM,
                    "Обнаружен debug/admin endpoint",
                    url,
                    method
                )
            )
        }

        // -----------------------
        // #10 Excessive resource consumption
        // -----------------------
        if (method.equals("POST", true) || method.equals("PUT", true)) {
            try {
                val heavyResp = authService.performRequestWithAuth(
                    methodFromString(method),
                    url,
                    bankBaseUrl,
                    clientId,
                    clientSecret,
                    consentId ?: "",
                    addClientIdToGet = false,
                    requireToken = true,
                    bodyBlock = {
                        ctx.headers.forEach { (k, v) -> header(k, v) }
                        setBody("""{"data": "${"A".repeat(5000)}"}""")
                    },
                    issues = issues
                )
                if (heavyResp.status.value in 200..299) {
                    issues.add(
                        Issue(
                            "UNRESTRICTED_RESOURCE_CONSUMPTION",
                            Severity.HIGH,
                            "Эндпоинт позволяет загружать чрезмерно большие данные",
                            url,
                            method
                        )
                    )
                }
            } catch (_: Exception) {}
        }
    }

    private suspend fun performInjectionTests(url: String, method: String, ctx: AttackContext, issues: MutableList<Issue>) {
        val payloads = listOf("'; DROP TABLE users;--", "\" OR \"1\"=\"1", "<script>alert(1)</script>")
        for (pl in payloads) {
            try {
                authService.performRequestWithAuth(
                    methodFromString(method),
                    url,
                    bankBaseUrl,
                    clientId,
                    clientSecret,
                    consentId ?: "",
                    addClientIdToGet = false,
                    requireToken = true,
                    bodyBlock = {
                        ctx.headers.forEach { (k, v) -> header(k, v) }
                        setBody("""{"test":"$pl"}""")
                    },
                    issues = issues
                )
            } catch (_: Exception) {}
        }
    }

    private suspend fun performMassAssignment(url: String, method: String, ctx: AttackContext, issues: MutableList<Issue>) {
        if (method.equals("POST", true) || method.equals("PUT", true)) {
            try {
                val resp = authService.performRequestWithAuth(
                    methodFromString(method),
                    url,
                    bankBaseUrl,
                    clientId,
                    clientSecret,
                    consentId ?: "",
                    addClientIdToGet = false,
                    requireToken = true,
                    bodyBlock = {
                        ctx.headers.forEach { (k, v) -> header(k, v) }
                        setBody("""{"role":"admin","balance":9999999}""")
                    },
                    issues = issues
                )
                if (resp.status.value in 200..299) {
                    issues.add(
                        Issue(
                            "MASS_ASSIGNMENT",
                            Severity.HIGH,
                            "Сервер принял неизвестные опасные поля",
                            url,
                            method
                        )
                    )
                }
            } catch (_: Exception) {}
        }
    }

    private suspend fun tokenBroken(url: String, method: String, issues: MutableList<Issue>): Boolean {
        return try {
            val r = client.request(url) { this.method = methodFromString(method) }
            r.status.value in 200..299
        } catch (_: Exception) { false }
    }

    private suspend fun checkRateLimiting(url: String, method: HttpMethod, issues: MutableList<Issue>) {
        var triggered = false
        repeat(5) {
            try {
                val resp = authService.performRequestWithAuth(
                    method,
                    url,
                    bankBaseUrl,
                    clientId,
                    clientSecret,
                    consentId ?: "",
                    addClientIdToGet = false,
                    requireToken = true,
                    bodyBlock = {},
                    issues = issues
                )
                if (resp.status.value == 429) triggered = true
            } catch (_: Exception) {}
        }
        if (!triggered) {
            issues.add(
                Issue(
                    "RATE_LIMITING",
                    Severity.MEDIUM,
                    "Нет защиты от частых запросов",
                    url,
                    method.value
                )
            )
        }
    }

    override suspend fun runCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        runSpecCheck(url, method, operation, issues)
        runAttackCheck(url, method, operation, issues)
    }
}

// --------------------
// Вспомогательная модель
// --------------------
class AttackContext(
    val headers: MutableMap<String, String> = mutableMapOf(),
    var body: String? = null
)

private fun methodFromString(m: String): HttpMethod =
    when (m.uppercase()) {
        "GET" -> HttpMethod.Get
        "POST" -> HttpMethod.Post
        "PUT" -> HttpMethod.Put
        "DELETE" -> HttpMethod.Delete
        "PATCH" -> HttpMethod.Patch
        "HEAD" -> HttpMethod.Head
        "OPTIONS" -> HttpMethod.Options
        else -> HttpMethod.Get
    }

private fun containsSensitiveField(body: String?): Boolean {
    if (body.isNullOrBlank()) return false
    val sensitive = listOf("password", "token", "secret", "ssn", "creditCard", "dob")
    return sensitive.any { body.contains(it, ignoreCase = true) }
}
