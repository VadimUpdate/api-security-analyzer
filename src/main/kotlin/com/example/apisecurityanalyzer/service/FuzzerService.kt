package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Расширенный фуззер: query params, request body, headers.
 * Параметры:
 *  - enabled: включён/выключен фуззинг
 *  - politenessDelayMs: задержка между запросами одной корутины
 *  - maxConcurrency: максимальное число параллельных "входов" фуззера
 *  - maxPayloadsPerEndpoint: ограничение payload'ов на endpoint
 *
 * Использует AuthService.performRequestWithAuth для единообразной аутентификации/логики retry.
 */
class FuzzerService(
    private val authService: AuthService,
    private val enabled: Boolean = true,
    private val politenessDelayMs: Long = 150,
    private val maxConcurrency: Int = 4,
    private val maxPayloadsPerEndpoint: Int = 10
) {

    // Базовый набор payloads — безопасно-агрессивные варианты (не destructive)
    private val basePayloads = listOf(
        // SQLi-ish
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1 --",
        // XSS-ish
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        // Path traversal
        "../etc/passwd",
        "..\\windows\\system32\\drivers\\etc\\hosts",
        // Lightweight command-like (non-destructive)
        "`; ls -la`",
        "; echo vuln",
        // Template/expansion probes
        "\${sleep 1}",
        "\${reboot}"
    )

    // Индикаторы в теле ответа, по которым считаем evidence
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

    /**
     * Основной внешний метод — фуззит endpoint по query/header/body (в зависимости от метода).
     * Возвращает быстро, если fuzzer отключён.
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
            // query param fuzz (GET)
            jobs += scope.async {
                sem.withPermit {
                    delay(politenessDelayMs)
                    try {
                        fuzzQuery(url, payload, issues)
                    } catch (_: Throwable) {
                        // swallow; network errors reported elsewhere
                    }
                }
            }

            // header fuzz (any method)
            jobs += scope.async {
                sem.withPermit {
                    delay(politenessDelayMs)
                    try {
                        fuzzHeader(url, method, payload, issues)
                    } catch (_: Throwable) {}
                }
            }

            // body fuzz only for methods that accept body
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
        val resp = authService.performRequestWithAuth(HttpMethod.Get, fuzzUrl, "", "", null, issues)
        val body = safeBodyText(resp)
        analyzeResponseForFuzz(fuzzUrl, "GET", payload, body, resp?.status?.value ?: 0, issues)
    }

    private suspend fun fuzzHeader(url: String, method: HttpMethod, payload: String, issues: MutableList<Issue>) {
        val resp = authService.performRequestWithAuth(method, url, "", "", {
            header("X-Scanner-Fuzz", payload)
            header("User-Agent", "ApiSecurityAnalyzer-Fuzzer/1.0")
        }, issues)
        val body = safeBodyText(resp)
        analyzeResponseForFuzz(url, method.value, payload, body, resp?.status?.value ?: 0, issues)
    }

    private suspend fun fuzzBody(url: String, method: HttpMethod, payload: String, issues: MutableList<Issue>) {
        val jsonBody = """{"__fuzz":"${escapeJson(payload)}"}"""
        val resp = authService.performRequestWithAuth(method, url, "", "", {
            contentType(ContentType.Application.Json)
            setBody(jsonBody)
            header("X-Scanner-Fuzz", "true")
            header("User-Agent", "ApiSecurityAnalyzer-Fuzzer/1.0")
        }, issues)
        val body = safeBodyText(resp)
        analyzeResponseForFuzz(url, method.value, payload, body, resp?.status?.value ?: 0, issues)
    }

    private fun analyzeResponseForFuzz(
        targetUrl: String,
        method: String,
        payload: String,
        responseBody: String,
        statusCode: Int,
        issues: MutableList<Issue>
    ) {
        // Собираем индикаторы
        val found = mutableListOf<String>()
        for (ind in evidenceIndicators) {
            if (responseBody.contains(ind, ignoreCase = true)) found += ind
        }

        // XSS
        if (responseBody.contains("<script", ignoreCase = true) || responseBody.contains("alert(", ignoreCase = true)) {
            addIfNotDuplicate(
                issues,
                Issue(
                    type = "XSS",
                    severity = Severity.HIGH,
                    description = "Потенциальная XSS через $method $targetUrl — payload: ${short(payload)} — found: ${found.take(4)}"
                )
            )
        }

        // SQLi / injection indicators
        if (found.any { it.contains("sql", ignoreCase = true) || it.contains("syntax", ignoreCase = true) || it.contains("SQLException", ignoreCase = true) }) {
            addIfNotDuplicate(
                issues,
                Issue(
                    type = "INJECTION",
                    severity = Severity.HIGH,
                    description = "Потенциальная инъекция (SQL/прочие) $method $targetUrl — payload: ${short(payload)} — indicators: ${found.take(5)} — HTTP $statusCode"
                )
            )
        }

        // Path traversal evidence
        if (responseBody.contains("root:x:", ignoreCase = true) || responseBody.contains("passwd", ignoreCase = true)) {
            addIfNotDuplicate(
                issues,
                Issue(
                    type = "PATH_TRAVERSAL",
                    severity = Severity.HIGH,
                    description = "Потенциальная утечка файлов при path traversal $method $targetUrl — payload: ${short(payload)}"
                )
            )
        }

        // Server error after payload may indicate vulnerability reached execution path
        if (statusCode >= 500) {
            addIfNotDuplicate(
                issues,
                Issue(
                    type = "SERVER_ERROR_ON_FUZZ",
                    severity = Severity.MEDIUM,
                    description = "Сервер возвращает $statusCode после payload (возможная уязвимость) $method $targetUrl — payload: ${short(payload)}"
                )
            )
        }
    }

    private fun short(s: String, limit: Int = 120) = if (s.length <= limit) s else s.take(limit) + "..."
    private fun encode(s: String) = java.net.URLEncoder.encode(s, "utf-8")
    private fun escapeJson(s: String) = s.replace("\"", "\\\"")

    // Простая Semaphore реализация на Mutex.withLock
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
                    try {
                        return block()
                    } finally {
                        mutex.withLock { available++ }
                    }
                } else {
                    // небольшая пауза прежде чем повторить попытку
                    delay(10)
                }
            }
        }
    }
}