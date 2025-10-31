package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.ScanReport
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.PathItem
import io.swagger.v3.oas.models.parameters.Parameter
import io.swagger.v3.parser.OpenAPIV3Parser
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.Instant

@Service
class ApiScanService {

    private val log = LoggerFactory.getLogger(javaClass)

    private val client = HttpClient(CIO) {
        install(HttpTimeout) {
            requestTimeoutMillis = 8_000
            connectTimeoutMillis = 5_000
            socketTimeoutMillis = 8_000
        }
        defaultRequest {
            header("User-Agent", "ApiSecurityAnalyzer/1.0")
            header("X-Scanner", "true")
        }
    }

    fun runScan(
        specUrl: String,
        targetUrl: String,
        maxConcurrency: Int = 4,
        politenessDelayMs: Int = 150
    ): ScanReport = runBlocking {
        val issues = mutableListOf<Issue>()

        // 1) загрузка спецификации
        val specText = try {
            client.get(specUrl).bodyAsText()
        } catch (e: Exception) {
            issues.add(
                Issue(
                    type = "SPEC_LOAD_ERROR",
                    path = specUrl,
                    method = "GET",
                    severity = "HIGH",
                    description = "Не удалось загрузить спецификацию",
                    evidence = e.message ?: "unknown"
                )
            )
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        val openApi = try {
            val result = OpenAPIV3Parser().readContents(specText, null, null)
            result.openAPI ?: throw IllegalStateException("parser returned null openAPI")
        } catch (e: Exception) {
            issues.add(
                Issue(
                    type = "SPEC_PARSE_ERROR",
                    path = specUrl,
                    method = "PARSE",
                    severity = "HIGH",
                    description = "Ошибка парсинга OpenAPI",
                    evidence = e.message ?: "unknown"
                )
            )
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        val pathsMap = openApi.paths ?: emptyMap()
        val totalEndpoints = pathsMap.size

        // Проверка доступности базового URL
        val reachable = checkTargetReachable(targetUrl, issues)
        if (!reachable) {
            return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())
        }

        val semaphore = Semaphore(maxConcurrency)
        val jobs = mutableListOf<Deferred<Unit>>()

        for ((pathTemplate, pathItem) in pathsMap) {
            val operations = extractOperations(pathItem)
            for ((method, operation) in operations) {
                if (operation == null) continue
                val combinedParams = (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())
                val testUrl = buildUrlFromPath(targetUrl, pathTemplate, combinedParams)

                val job = async {
                    semaphore.withPermit {
                        delay(politenessDelayMs.toLong())
                        try {
                            runChecksForPath(testUrl, method, operation.requestBody != null, issues)
                        } catch (e: Exception) {
                            log.debug("Check failed for {} {}: {}", method, testUrl, e.message)
                            addNetworkIssue(issues, testUrl, method, "Ошибка при проверке эндпоинта", e.message ?: "unknown")
                        }
                    }
                }
                jobs += job
            }
        }

        jobs.awaitAll()
        runGlobalChecks(targetUrl, issues)

        return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())
    }

    // -----------------------
    // Проверки по эндпоинту
    // -----------------------
    private suspend fun runChecksForPath(testUrl: String, method: String, hasRequestBody: Boolean, issues: MutableList<Issue>) {
        if (method.equals("GET", true)) {
            try {
                val resp: HttpResponse = client.get(testUrl)
                val code = resp.status.value
                if (code in 200..299) {
                    val body = safeBodyText(resp)
                    if (containsSensitiveField(body)) {
                        addIfNotDuplicate(
                            issues,
                            Issue(
                                type = "EXCESSIVE_DATA_EXPOSURE",
                                path = testUrl,
                                method = "GET",
                                severity = "HIGH",
                                description = "Ответ содержит возможные чувствительные поля",
                                evidence = body.take(1000)
                            )
                        )
                    }
                    if (Regex("/\\d+").containsMatchIn(testUrl) || testUrl.endsWith("/1")) {
                        addIfNotDuplicate(
                            issues,
                            Issue(
                                type = "BOLA",
                                path = testUrl,
                                method = "GET",
                                severity = "MEDIUM",
                                description = "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA",
                                evidence = "HTTP $code"
                            )
                        )
                    }
                } else {
                    addIfNotDuplicate(
                        issues,
                        Issue(
                            type = "ENDPOINT_ERROR_STATUS",
                            path = testUrl,
                            method = "GET",
                            severity = if (code >= 500) "HIGH" else "LOW",
                            description = "Эндпоинт вернул HTTP $code",
                            evidence = "HTTP $code"
                        )
                    )
                }
            } catch (e: Exception) {
                addNetworkIssue(issues, testUrl, "GET", "Ошибка сети при GET", e.message ?: "unknown")
            }
        }

        // Проверка /admin
        try {
            val adminUrl = testUrl.trimEnd('/') + "/admin"
            val adminResp: HttpResponse = client.get(adminUrl)
            if (adminResp.status.value in 200..299) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "BROKEN_FUNCTION_LEVEL_AUTH",
                        path = adminUrl,
                        method = "GET",
                        severity = "HIGH",
                        description = "Административный эндпоинт доступен публично",
                        evidence = "HTTP ${adminResp.status.value}"
                    )
                )
            }
        } catch (e: Exception) {
            addNetworkIssue(issues, testUrl + "/admin", "GET", "Ошибка сети при проверке /admin", e.message ?: "unknown")
        }

        // Инъекции
        try {
            val injUrl = if (testUrl.contains("?")) "$testUrl&debug=' OR '1'='1" else "$testUrl?debug=' OR '1'='1"
            val injResp: HttpResponse = client.get(injUrl)
            if (injResp.status.value in 200..299) {
                val body = safeBodyText(injResp)
                if (body.contains("syntax", true) || body.contains("sql", true) || body.contains("exception", true)) {
                    addIfNotDuplicate(
                        issues,
                        Issue(
                            type = "INJECTION",
                            path = injUrl,
                            method = "GET",
                            severity = "HIGH",
                            description = "Потенциальная инъекция",
                            evidence = body.take(1000)
                        )
                    )
                }
            }
        } catch (e: Exception) {
            addNetworkIssue(issues, testUrl, "GET", "Ошибка сети при injection probe", e.message ?: "unknown")
        }

        // POST Mass Assignment
        if (method.equals("POST", true) && hasRequestBody) {
            try {
                val resp: HttpResponse = client.post(testUrl) {
                    contentType(ContentType.Application.Json)
                    header("X-Scanner-Probe", "true")
                    setBody("""{"__scanner_probe":true,"role":"admin","isAdmin":true}""")
                }
                val code = resp.status.value
                val body = safeBodyText(resp)
                if (code in 200..299 && !body.contains("error", true) && !body.contains("validation", true)) {
                    addIfNotDuplicate(
                        issues,
                        Issue(
                            type = "MASS_ASSIGNMENT",
                            path = testUrl,
                            method = "POST",
                            severity = "MEDIUM",
                            description = "POST принял дополнительные/административные поля",
                            evidence = "HTTP $code, body: ${body.take(500)}"
                        )
                    )
                }
            } catch (e: Exception) {
                addNetworkIssue(issues, testUrl, "POST", "Ошибка сети при POST probe", e.message ?: "unknown")
            }
        }
    }

    // -----------------------
    // Глобальные проверки
    // -----------------------
    private suspend fun runGlobalChecks(baseUrl: String, issues: MutableList<Issue>) {
        try {
            var success = 0
            repeat(6) {
                val resp = client.get("$baseUrl/health")
                if (resp.status.value in 200..299) success++
            }
            if (success >= 5) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "RATE_LIMITING",
                        path = "$baseUrl/health",
                        method = "GET",
                        severity = "MEDIUM",
                        description = "Похоже, нет ограничителя запросов",
                        evidence = "$success quick calls succeeded"
                    )
                )
            }
        } catch (_: Exception) {}

        val docPaths = listOf("/swagger-ui.html", "/swagger-ui/", "/docs", "/api-docs", "/swagger", "/redoc")
        for (p in docPaths) {
            try {
                val resp = client.get("$baseUrl$p")
                if (resp.status.value in 200..299) {
                    addIfNotDuplicate(
                        issues,
                        Issue(
                            type = "SECURITY_MISCONFIGURATION",
                            path = "$baseUrl$p",
                            method = "GET",
                            severity = "MEDIUM",
                            description = "Документация / Swagger UI доступна публично",
                            evidence = "HTTP ${resp.status.value}"
                        )
                    )
                }
            } catch (_: Exception) {}
        }

        val sensitive = listOf("/.env", "/.git/config", "/.gitignore", "/.htpasswd")
        for (p in sensitive) {
            try {
                val resp = client.request("$baseUrl$p") { method = HttpMethod.Head }
                if (resp.status.value in 200..299) {
                    addIfNotDuplicate(
                        issues,
                        Issue(
                            type = "IMPROPER_ASSETS",
                            path = "$baseUrl$p",
                            method = "HEAD",
                            severity = "HIGH",
                            description = "Чувствительный файл доступен по HTTP",
                            evidence = "HTTP ${resp.status.value}"
                        )
                    )
                }
            } catch (_: Exception) {}
        }

        try {
            val resp = client.get("$baseUrl/nonexistent_endpoint_for_logging_test_12345")
            val body = safeBodyText(resp)
            if (body.contains("Exception", true) || body.contains("StackTrace", true) || body.contains("at ")) {
                addIfNotDuplicate(
                    issues,
                    Issue(
                        type = "INSUFFICIENT_LOGGING",
                        path = "$baseUrl/nonexistent_endpoint_for_logging_test_12345",
                        method = "GET",
                        severity = "MEDIUM",
                        description = "Сервер возвращает подробные ошибки/стек-трейс в теле ответа",
                        evidence = body.take(1000)
                    )
                )
            }
        } catch (_: Exception) {}
    }

    // -----------------------
    // Вспомогательные функции
    // -----------------------
    private fun addIfNotDuplicate(list: MutableList<Issue>, issue: Issue) {
        val exists = list.any { it.type == issue.type && it.path == issue.path && it.method == issue.method }
        if (!exists) list.add(issue)
    }

    private fun addNetworkIssue(list: MutableList<Issue>, path: String, method: String, desc: String, evidence: String) {
        val issue = Issue(
            type = "NETWORK_OR_CONFIGURATION",
            path = path,
            method = method,
            severity = "LOW",
            description = desc,
            evidence = evidence
        )
        addIfNotDuplicate(list, issue)
    }

    private fun containsSensitiveField(body: String?): Boolean {
        if (body == null) return false
        val keys = listOf("password", "ssn", "creditCard", "cardNumber", "cvv", "secret", "token", "access_token")
        return keys.any { body.contains(it, ignoreCase = true) }
    }

    private suspend fun safeBodyText(resp: HttpResponse): String {
        return try {
            resp.bodyAsText()
        } catch (e: Exception) {
            ""
        }
    }

    private fun extractOperations(pathItem: PathItem): Map<String, io.swagger.v3.oas.models.Operation> {
        val map = mutableMapOf<String, io.swagger.v3.oas.models.Operation>()
        pathItem.get?.let { map["GET"] = it }
        pathItem.post?.let { map["POST"] = it }
        pathItem.put?.let { map["PUT"] = it }
        pathItem.delete?.let { map["DELETE"] = it }
        pathItem.patch?.let { map["PATCH"] = it }
        pathItem.head?.let { map["HEAD"] = it }
        pathItem.options?.let { map["OPTIONS"] = it }
        return map
    }

    private fun buildUrlFromPath(base: String, pathTemplate: String, parameters: List<Parameter>?): String {
        var url = pathTemplate
        parameters?.forEach { p ->
            val name = p.name ?: return@forEach
            val example = when {
                p.schema?.example != null -> p.schema.example.toString()
                p.schema?.type == "integer" -> "1"
                p.schema?.type == "number" -> "1"
                p.schema?.type == "boolean" -> "true"
                p.schema?.type == "string" -> "test"
                else -> "test"
            }
            url = url.replace("{$name}", example)
        }
        url = url.replace(Regex("\\{[^}]+\\}"), "test")
        val baseNormalized = if (base.endsWith("/")) base.dropLast(1) else base
        val pathNormalized = if (!url.startsWith("/")) "/$url" else url
        return baseNormalized + pathNormalized
    }

    private suspend fun checkTargetReachable(baseUrl: String, issues: MutableList<Issue>): Boolean {
        try {
            val resp = client.request(baseUrl) { method = HttpMethod.Head }
            val code = resp.status.value
            if (code in 200..399) return true
            addNetworkIssue(
                issues,
                baseUrl,
                "HEAD",
                "Базовый URL ответил кодом $code — возможно неверный base path или конфигурация сервера",
                "HTTP $code"
            )
            return false
        } catch (e: Exception) {
            addNetworkIssue(
                issues,
                baseUrl,
                "HEAD",
                "Не удалось подключиться к базовому URL — проверьте host/путь/сетевые настройки",
                e.message ?: "unknown"
            )
            return false
        }
    }
}
