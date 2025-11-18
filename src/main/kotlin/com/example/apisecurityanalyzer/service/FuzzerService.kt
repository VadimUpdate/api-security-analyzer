package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.ktor.client.statement.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class FuzzerService(
    private val authService: AuthService,
    private val bankBaseUrl: String,
    private val clientId: String,
    private val clientSecret: String,
    private val enabled: Boolean = true,
    private val politenessDelayMs: Long = 150,
    private val maxConcurrency: Int = 4,
    private val maxPayloadsPerEndpoint: Int = 10
) {
    var bankToken: String = ""
    var consentId: String = ""

    data class BaselineRequest(
        val url: String,
        val method: HttpMethod,
        val headers: Map<String, String>,
        val body: String?
    )

    private val attackCategories = listOf(
        "SQL Injection",
        "XSS",
        "Path Traversal",
        "Command Injection",
        "Mass Assignment",
        "SSRF",
        "RCE-Like",
        "LDAP Injection",
        "NoSQL Injection",
        "Broken Input Validation"
    )

    private val payloadBank: Map<String, List<String>> = mapOf(
        "SQL Injection" to listOf(
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1 --",
            "1 OR 1=1",
            "' UNION SELECT NULL--"
        ),
        "XSS" to listOf(
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "<img src=x onerror=alert(document.cookie)>"
        ),
        "Path Traversal" to listOf(
            "../../etc/passwd",
            "/../../../../var/log",
            "..\\..\\windows\\system.ini"
        ),
        "Command Injection" to listOf(
            "`; ls -la`",
            "value && whoami",
            "test; cat /etc/passwd"
        ),
        "Mass Assignment" to listOf(
            "{\"role\":\"admin\"}",
            "{\"is_superuser\":true}",
            "{\"balance\":999999999}"
        ),
        "SSRF" to listOf(
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:8080/admin"
        ),
        "RCE-Like" to listOf(
            "\${7*7}",
            "#{7*7}",
            "$(touch /tmp/rce)"
        ),
        "LDAP Injection" to listOf(
            "*)(uid=*))(|(uid=*",
            "(|(objectClass=*))"
        ),
        "NoSQL Injection" to listOf(
            "{ \"\$ne\": null }",
            "{ \"\$gt\": \"\" }"
        ),
        "Broken Input Validation" to listOf(
            "A".repeat(4000),
            "🔥💣💥",
            "😀😀😀😀😀😀😀😀"
        )
    )

    private val evidenceIndicators = listOf(
        "syntax error",
        "sql",
        "SQLException",
        "SQL syntax",
        "stacktrace",
        "StackTrace",
        "<script",
        "alert(",
        "root:x:",
        "passwd",
        "exception",
        "unauthorized",
        "constraint"
    )

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    suspend fun fuzzEndpoint(
        url: String,
        method: HttpMethod,
        issues: MutableList<Issue>,
        allowedPayloads: List<String>? = null
    ) {
        if (!enabled || url.endsWith("/auth/bank-token")) return

        ensureAuth(issues)

        val baselineResp = try {
            authService.performRequestWithAuth(
                method = method,
                url = url,
                bankBaseUrl = bankBaseUrl,
                clientId = clientId,
                clientSecret = clientSecret,
                consentId = consentId,
                addClientIdToGet = false,
                bodyBlock = {},
                issues = issues
            )
        } catch (_: Throwable) {
            return
        }

        val baselineCode = baselineResp.status.value
        val baselineBody = safeBodyText(baselineResp)

        if (baselineCode != 200) return

        val baselineHeaders = baselineResp.headers.entries().associate { it.key to it.value.joinToString() }

        val baselineRequest = BaselineRequest(
            url = url,
            method = method,
            headers = baselineHeaders,
            body = baselineBody
        )

        val categoryPayloads = if (allowedPayloads != null)
            allowedPayloads
        else
            attackCategories.flatMap { payloadBank[it]!! }
                .take(maxPayloadsPerEndpoint)

        val sem = Semaphore(maxConcurrency)
        val jobs = mutableListOf<Deferred<Unit>>()

        for (payload in categoryPayloads) {

            jobs += scope.async {
                sem.withPermit {
                    delay(politenessDelayMs)
                    fuzzQuery(baselineRequest, payload, issues)
                }
            }

            jobs += scope.async {
                sem.withPermit {
                    delay(politenessDelayMs)
                    fuzzHeader(baselineRequest, payload, issues)
                }
            }

            if (method in listOf(HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete)
                && !isStrictEndpoint(url)) {

                jobs += scope.async {
                    sem.withPermit {
                        delay(politenessDelayMs)
                        fuzzBody(baselineRequest, payload, issues)
                    }
                }
            }
        }

        jobs.awaitAll()
    }

    private suspend fun ensureAuth(issues: MutableList<Issue>) {
        if (bankToken.isBlank() || consentId.isBlank()) {
            bankToken = authService.getBankToken(bankBaseUrl, clientId, clientSecret, issues)
            consentId = authService.createConsent(bankBaseUrl, clientId, clientSecret, issues)
        }
    }

    private fun isStrictEndpoint(url: String): Boolean {
        val clean = url.lowercase()
        return clean.contains("/accounts") &&
                (clean.endsWith("/accounts") ||
                        clean.contains("/close") ||
                        clean.contains("/transfer") ||
                        clean.contains("/donate"))
    }

    private suspend fun fuzzQuery(
        baseline: BaselineRequest,
        payload: String,
        issues: MutableList<Issue>
    ) {
        val category = detectAttackType(payload)

        logFuzz("QUERY", category, baseline.method, baseline.url, payload)

        val fuzzUrl =
            if (baseline.url.contains("?"))
                "${baseline.url}&fuzz=${encode(payload)}"
            else
                "${baseline.url}?fuzz=${encode(payload)}"

        val resp = authService.performRequestWithAuth(
            method = baseline.method,
            url = fuzzUrl,
            bankBaseUrl = bankBaseUrl,
            clientId = clientId,
            clientSecret = clientSecret,
            consentId = consentId,
            addClientIdToGet = false,
            bodyBlock = { baseline.body?.let { setBody(it) } },
            issues = issues
        )

        analyzeResponseForFuzz(
            fuzzUrl,
            baseline.method.value,
            payload,
            safeBodyText(resp),
            resp.status.value,
            category,
            issues
        )
    }

    private suspend fun fuzzHeader(
        baseline: BaselineRequest,
        payload: String,
        issues: MutableList<Issue>
    ) {
        val category = detectAttackType(payload)

        logFuzz("HEADER", category, baseline.method, baseline.url, payload)

        val resp = authService.performRequestWithAuth(
            method = baseline.method,
            url = baseline.url,
            bankBaseUrl = bankBaseUrl,
            clientId = clientId,
            clientSecret = clientSecret,
            consentId = consentId,
            addClientIdToGet = false,
            bodyBlock = {
                baseline.body?.let { setBody(it) }
                baseline.headers.forEach { (k, v) -> header(k, v) }
                header("X-Fuzzer", payload)
            },
            issues = issues
        )

        analyzeResponseForFuzz(
            baseline.url,
            baseline.method.value,
            payload,
            safeBodyText(resp),
            resp.status.value,
            category,
            issues
        )
    }

    private suspend fun fuzzBody(
        baseline: BaselineRequest,
        payload: String,
        issues: MutableList<Issue>
    ) {
        val category = detectAttackType(payload)

        logFuzz("BODY", category, baseline.method, baseline.url, payload)

        val fuzzJson = """{"__fuzz":"${escapeJson(payload)}"}"""

        val resp = authService.performRequestWithAuth(
            method = baseline.method,
            url = baseline.url,
            bankBaseUrl = bankBaseUrl,
            clientId = clientId,
            clientSecret = clientSecret,
            consentId = consentId,
            addClientIdToGet = false,
            bodyBlock = {
                contentType(ContentType.Application.Json)
                setBody(fuzzJson)
                header("X-Fuzzer", "true")
            },
            issues = issues
        )

        analyzeResponseForFuzz(
            baseline.url,
            baseline.method.value,
            payload,
            safeBodyText(resp),
            resp.status.value,
            category,
            issues
        )
    }

    private fun logFuzz(
        phase: String,
        category: String,
        method: HttpMethod,
        url: String,
        payload: String
    ) {
        println(
            "\n====== FUZZ ATTACK ======\n" +
                    "Phase: $phase\n" +
                    "Category: $category\n" +
                    "URL: $url\n" +
                    "Method: ${method.value}\n" +
                    "Payload:\n$payload\n" +
                    "=========================\n"
        )
    }

    /** Исправлено: теперь ищем payload по contains(), а не equals */
    private fun detectAttackType(payload: String): String {
        for ((category, items) in payloadBank) {
            if (items.any { payload.contains(it, ignoreCase = true) || it.contains(payload) })
                return category
        }
        return "Unknown"
    }

    private fun analyzeResponseForFuzz(
        targetUrl: String,
        method: String,
        payload: String,
        responseBody: String,
        statusCode: Int,
        category: String,
        issues: MutableList<Issue>
    ) {
        val evidence = evidenceIndicators.filter { responseBody.contains(it, ignoreCase = true) }

        if (evidence.isNotEmpty()) {
            addIfNotDuplicate(
                issues,
                Issue(
                    category.uppercase(),
                    Severity.HIGH,
                    "Индикаторы: $evidence | payload=${short(payload)}",
                    targetUrl,
                    method
                )
            )
        }

        if (category == "XSS" && responseBody.contains("<script", ignoreCase = true))
            addIssue(issues, "XSS", Severity.HIGH, targetUrl, method, payload)

        if (category == "SQL Injection" && responseBody.contains("sql", ignoreCase = true))
            addIssue(issues, "SQLI", Severity.HIGH, targetUrl, method, payload)

        if (category == "Path Traversal" &&
            (responseBody.contains("root:x:") || responseBody.contains("passwd"))
        )
            addIssue(issues, "PATH_TRAVERSAL", Severity.HIGH, targetUrl, method, payload)

        if (category == "SSRF" && statusCode in listOf(500, 502, 503))
            addIssue(issues, "SSRF", Severity.MEDIUM, targetUrl, method, payload)

        if (statusCode >= 500)
            addIssue(
                issues,
                "SERVER_ERROR_ON_FUZZ",
                Severity.MEDIUM,
                targetUrl,
                method,
                "HTTP $statusCode after fuzz"
            )
    }

    private fun addIssue(
        issues: MutableList<Issue>,
        type: String,
        severity: Severity,
        url: String,
        method: String,
        payload: String
    ) {
        addIfNotDuplicate(
            issues,
            Issue(
                type,
                severity,
                "Payload=${short(payload)}",
                url,
                method
            )
        )
    }

    private fun short(s: String, limit: Int = 120): String =
        if (s.length <= limit) s else s.take(limit) + "..."

    private fun encode(s: String): String =
        java.net.URLEncoder.encode(s, "utf-8")

    private fun escapeJson(s: String): String =
        s.replace("\"", "\\\"")

    private fun addIfNotDuplicate(list: MutableList<Issue>, issue: Issue) {
        if (list.none { it.type == issue.type && it.url == issue.url && it.method == issue.method }) {
            list += issue
        }
    }

    private fun safeBodyText(resp: HttpResponse): String =
        try {
            runBlocking { resp.bodyAsText() }
        } catch (_: Throwable) {
            ""
        }

    private class Semaphore(private val permits: Int) {
        private val mutex = Mutex()
        private var available = permits

        suspend fun <T> withPermit(block: suspend () -> T): T {
            while (true) {
                var allowed = false

                mutex.withLock {
                    if (available > 0) {
                        available--
                        allowed = true
                    }
                }

                if (allowed) {
                    return try {
                        block()
                    } finally {
                        mutex.withLock { available++ }
                    }
                } else {
                    delay(10)
                }
            }
        }
    }
}
