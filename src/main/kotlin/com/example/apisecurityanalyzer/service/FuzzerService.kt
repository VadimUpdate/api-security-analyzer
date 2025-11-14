package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Фуззер для API: query params, headers, body.
 * Параметры:
 * - enabled: включён/выключен
 * - politenessDelayMs: задержка между запросами одной корутины
 * - maxConcurrency: параллельные "потоки" фуззера
 * - maxPayloadsPerEndpoint: ограничение payload'ов на endpoint
 *
 * Использует AuthService.performRequestWithAuth для унифицированной аутентификации.
 */
class FuzzerService(
    private val authService: AuthService,
    private val enabled: Boolean = true,
    private val politenessDelayMs: Long = 150,
    private val maxConcurrency: Int = 4,
    private val maxPayloadsPerEndpoint: Int = 10
) {

    private val basePayloads = listOf(
        "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 --",
        "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
        "../etc/passwd", "..\\windows\\system32\\drivers\\etc\\hosts",
        "`; ls -la`", "; echo vuln",
        "\${sleep 1}", "\${reboot}"
    )

    private val evidenceIndicators = listOf(
        "syntax error", "sql", "SQLException", "SQL syntax",
        "stacktrace", "StackTrace", "<script", "alert(", "root:x:", "passwd",
        "exception", "unauthorized", "constraint"
    )

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Основной метод — фуззит endpoint по query/header/body.
     */
    suspend fun fuzzEndpoint(
        url: String,
        method: HttpMethod,
        issues: MutableList<Issue>,
        allowedPayloads: List<String>? = null
    ) {
        if (!enabled) return

        val payloads = (allowedPayloads ?: basePayloads).take(maxPayloadsPerEndpoint)
        val jobs = mutableListOf<Deferred<Unit>>()
        val sem = Semaphore(maxConcurrency)

        for (payload in payloads) {
            // query param fuzz
            jobs += scope.async {
                sem.withPermit {
                    delay(politenessDelayMs)
                    try {
                        fuzzQuery(url, payload, issues)
                    } catch (_: Throwable) {}
                }
            }

            // header fuzz
            jobs += scope.async {
                sem.withPermit {
                    delay(politenessDelayMs)
                    try {
                        fuzzHeader(url, method, payload, issues)
                    } catch (_: Throwable) {}
                }
            }

            // body fuzz
            if (method in listOf(HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete)) {
                jobs += scope.async {
                    sem.withPermit {
                        delay(politenessDelayMs)
                        try {
                            fuzzBody(url, method, payload, issues)
                        } catch (_: Throwable) {}
                    }
                }
            }
        }

        jobs.awaitAll()
    }

    private suspend fun fuzzQuery(url: String, payload: String, issues: MutableList<Issue>) {
        val fuzzUrl = if (url.contains("?")) "$url&fuzz=${encode(payload)}" else "$url?fuzz=${encode(payload)}"
        val resp = authService.performRequestWithAuth(
            method = HttpMethod.Get,
            url = fuzzUrl,
            clientId = "",
            clientSecret = "",
            openApi = null,
            bodyBlock = null,
            issues = issues
        )
        analyzeResponse(fuzzUrl, "GET", payload, safeBodyText(resp), resp?.status?.value ?: 0, issues)
    }

    private suspend fun fuzzHeader(url: String, method: HttpMethod, payload: String, issues: MutableList<Issue>) {
        val resp = authService.performRequestWithAuth(
            method = method,
            url = url,
            clientId = "",
            clientSecret = "",
            openApi = null,
            bodyBlock = {
                header("X-Scanner-Fuzz", payload)
                header("User-Agent", "ApiSecurityAnalyzer-Fuzzer/1.0")
            },
            issues = issues
        )
        analyzeResponse(url, method.value, payload, safeBodyText(resp), resp?.status?.value ?: 0, issues)
    }

    private suspend fun fuzzBody(url: String, method: HttpMethod, payload: String, issues: MutableList<Issue>) {
        val jsonBody = """{"__fuzz":"${escapeJson(payload)}"}"""
        val resp = authService.performRequestWithAuth(
            method = method,
            url = url,
            clientId = "",
            clientSecret = "",
            openApi = null,
            bodyBlock = {
                contentType(ContentType.Application.Json)
                setBody(jsonBody)
                header("X-Scanner-Fuzz", "true")
                header("User-Agent", "ApiSecurityAnalyzer-Fuzzer/1.0")
            },
            issues = issues
        )
        analyzeResponse(url, method.value, payload, safeBodyText(resp), resp?.status?.value ?: 0, issues)
    }

    private fun analyzeResponse(
        targetUrl: String,
        method: String,
        payload: String,
        responseBody: String,
        statusCode: Int,
        issues: MutableList<Issue>
    ) {
        val found = evidenceIndicators.filter { responseBody.contains(it, ignoreCase = true) }

        if (responseBody.contains("<script", ignoreCase = true) || responseBody.contains("alert(", ignoreCase = true)) {
            addIfNotDuplicate(
                issues, Issue(
                    type = "XSS",
                    severity = Severity.HIGH,
                    description = "Потенциальная XSS через $method $targetUrl — payload: ${short(payload)} — found: ${found.take(4)}"
                )
            )
        }

        if (found.any { it.contains("sql", ignoreCase = true) || it.contains("syntax", ignoreCase = true) || it.contains("SQLException", ignoreCase = true) }) {
            addIfNotDuplicate(
                issues, Issue(
                    type = "INJECTION",
                    severity = Severity.HIGH,
                    description = "Потенциальная инъекция $method $targetUrl — payload: ${short(payload)} — indicators: ${found.take(5)} — HTTP $statusCode"
                )
            )
        }

        if (responseBody.contains("root:x:", ignoreCase = true) || responseBody.contains("passwd", ignoreCase = true)) {
            addIfNotDuplicate(
                issues, Issue(
                    type = "PATH_TRAVERSAL",
                    severity = Severity.HIGH,
                    description = "Потенциальная утечка файлов $method $targetUrl — payload: ${short(payload)}"
                )
            )
        }

        if (statusCode >= 500) {
            addIfNotDuplicate(
                issues, Issue(
                    type = "SERVER_ERROR_ON_FUZZ",
                    severity = Severity.MEDIUM,
                    description = "Сервер возвращает $statusCode после payload $method $targetUrl — payload: ${short(payload)}"
                )
            )
        }
    }

    private fun short(s: String, limit: Int = 120) = if (s.length <= limit) s else s.take(limit) + "..."
    private fun encode(s: String) = java.net.URLEncoder.encode(s, "utf-8")
    private fun escapeJson(s: String) = s.replace("\"", "\\\"")

    // Semaphore для ограничения concurrency
    private class Semaphore(private val permits: Int) {
        private val mutex = Mutex()
        private var available = permits

        suspend fun <T> withPermit(block: suspend () -> T): T {
            while (true) {
                var allowed = false
                mutex.withLock { if (available > 0) { available--; allowed = true } }
                if (allowed) {
                    try { return block() }
                    finally { mutex.withLock { available++ } }
                } else delay(10)
            }
        }
    }

    private fun safeBodyText(resp: Any?): String {
        return try {
            val bodyMethod = resp?.javaClass?.methods?.firstOrNull { it.name == "bodyAsText" }
            bodyMethod?.invoke(resp) as? String ?: ""
        } catch (_: Exception) {
            ""
        }
    }

    private fun addIfNotDuplicate(issues: MutableList<Issue>, issue: Issue) {
        if (issues.none { it.description == issue.description && it.type == issue.type }) {
            issues.add(issue)
        }
    }
}
