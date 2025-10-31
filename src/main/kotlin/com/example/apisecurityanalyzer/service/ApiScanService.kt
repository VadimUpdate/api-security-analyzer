package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.ScanReport
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.PathItem
import io.swagger.v3.oas.models.Operation
import io.swagger.v3.oas.models.parameters.Parameter
import io.swagger.v3.oas.models.responses.ApiResponse
import io.swagger.v3.oas.models.media.Schema
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
    private val mapper = jacksonObjectMapper()

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

        // 1) загрузка спецификации (текст)
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

        // 2) parse OpenAPI
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
        val totalEndpoints = pathsMap.entries.sumOf { entry ->
            // count methods per path
            val ops = extractOperations(entry.value)
            ops.size
        }

        // 3) проверка доступности базового URL, fallback на первый путь если HEAD=405
        val reachable = checkTargetReachable(targetUrl, pathsMap.keys, issues)
        if (!reachable) {
            return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())
        }

        // 4) параллельный обход эндпоинтов
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
                            runChecksForPath(testUrl, method, operation, issues)
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

        // 5) глобальные проверки
        runGlobalChecks(targetUrl, issues)

        return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())
    }

    // -----------------------
    // Пер-путь проверки
    // -----------------------
    private suspend fun runChecksForPath(testUrl: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        // GET-flow: status, schema validation, sensitive data, BOLA, IDOR, Broken Auth
        if (method.equals("GET", true)) {
            try {
                val resp: HttpResponse = client.get(testUrl)
                val code = resp.status.value
                val body = safeBodyText(resp)

                if (code in 200..299) {
                    // schema validation: try to pick 200 or default response schema
                    val responsesMap = operation.responses ?: emptyMap()
                    val responseSpec = responsesMap["200"] ?: responsesMap["201"] ?: responsesMap["default"] ?: responsesMap.values.firstOrNull()
                    if (responseSpec != null) {
                        val schema = responseSpec.content?.get("application/json")?.schema
                        if (schema != null) {
                            val schemaErrors = validateResponseSchema(body, schema)
                            schemaErrors.forEach { err ->
                                addIfNotDuplicate(issues, Issue("SCHEMA_MISMATCH", testUrl, method, "MEDIUM", err, body.take(500)))
                            }
                        }
                    }

                    // sensitive data
                    if (containsSensitiveField(body)) {
                        addIfNotDuplicate(
                            issues,
                            Issue("EXCESSIVE_DATA_EXPOSURE", testUrl, method, "HIGH", "Ответ содержит возможные чувствительные поля", body.take(1000))
                        )
                    }

                    // BOLA heuristic
                    if (Regex("/\\d+").containsMatchIn(testUrl) || testUrl.endsWith("/1")) {
                        addIfNotDuplicate(
                            issues,
                            Issue("BOLA", testUrl, method, "MEDIUM", "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA", "HTTP $code")
                        )
                    }

                    // IDOR
                    checkIDOR(testUrl, method, issues)

                    // Broken Authentication: if operation declares security requirements, check access without tokens
                    val requiresAuth = (operation.security != null && operation.security.isNotEmpty()) || (operation.responses?.keys?.contains("401") == true)
                    if (requiresAuth) {
                        checkBrokenAuth(testUrl, method, issues)
                    }
                } else {
                    addIfNotDuplicate(
                        issues,
                        Issue("ENDPOINT_ERROR_STATUS", testUrl, method, if (code >= 500) "HIGH" else "LOW", "Эндпоинт вернул HTTP $code", "HTTP $code")
                    )
                }
            } catch (e: Exception) {
                addNetworkIssue(issues, testUrl, "GET", "Ошибка сети при GET", e.message ?: "unknown")
            }
        }

        // --- admin check (common) ---
        try {
            val adminUrl = testUrl.trimEnd('/') + "/admin"
            val adminResp: HttpResponse = client.get(adminUrl)
            if (adminResp.status.value in 200..299) {
                addIfNotDuplicate(issues, Issue("BROKEN_FUNCTION_LEVEL_AUTH", adminUrl, "GET", "HIGH", "Административный эндпоинт доступен публично", "HTTP ${adminResp.status.value}"))
            }
        } catch (e: Exception) {
            addNetworkIssue(issues, testUrl + "/admin", "GET", "Ошибка сети при проверке /admin", e.message ?: "unknown")
        }

        // --- injection probe ---
        try {
            val injUrl = if (testUrl.contains("?")) "$testUrl&debug=' OR '1'='1" else "$testUrl?debug=' OR '1'='1"
            val injResp: HttpResponse = client.get(injUrl)
            if (injResp.status.value in 200..299) {
                val body = safeBodyText(injResp)
                if (body.contains("syntax", true) || body.contains("sql", true) || body.contains("exception", true)) {
                    addIfNotDuplicate(issues, Issue("INJECTION", injUrl, "GET", "HIGH", "Потенциальная инъекция", body.take(1000)))
                }
            }
        } catch (e: Exception) {
            addNetworkIssue(issues, testUrl, "GET", "Ошибка сети при injection probe", e.message ?: "unknown")
        }

        // --- POST Mass Assignment ---
        if (method.equals("POST", true) && operation.requestBody != null) {
            try {
                val resp: HttpResponse = client.post(testUrl) {
                    contentType(ContentType.Application.Json)
                    header("X-Scanner-Probe", "true")
                    setBody("""{"__scanner_probe":true,"role":"admin","isAdmin":true}""")
                }
                val code = resp.status.value
                val body = safeBodyText(resp)
                if (code in 200..299 && !body.contains("error", true) && !body.contains("validation", true)) {
                    addIfNotDuplicate(issues, Issue("MASS_ASSIGNMENT", testUrl, "POST", "MEDIUM", "POST принял дополнительные/административные поля", "HTTP $code, body: ${body.take(500)}"))
                }
            } catch (e: Exception) {
                addNetworkIssue(issues, testUrl, "POST", "Ошибка сети при POST probe", e.message ?: "unknown")
            }
        }
    }

    // -----------------------
    // Новые проверки
    // -----------------------
    private suspend fun checkIDOR(testUrl: String, method: String, issues: MutableList<Issue>) {
        if (!method.equals("GET", true)) return
        val alteredUrl = testUrl.replace(Regex("/\\d+")) { "/999999" }
        if (alteredUrl == testUrl) return // нет числового сегмента
        try {
            val resp = client.get(alteredUrl)
            if (resp.status.value in 200..299) {
                addIfNotDuplicate(issues, Issue("IDOR", alteredUrl, "GET", "HIGH", "Публичный доступ к чужому ресурсу (IDOR)", "HTTP ${resp.status.value}"))
            }
        } catch (_: Exception) {
        }
    }

    private suspend fun checkBrokenAuth(testUrl: String, method: String, issues: MutableList<Issue>) {
        try {
            val resp = client.get(testUrl) // без токена
            if (resp.status.value in 200..299) {
                addIfNotDuplicate(issues, Issue("BROKEN_AUTH", testUrl, method, "HIGH", "Эндпоинт доступен без аутентификации", "HTTP ${resp.status.value}"))
            }
        } catch (_: Exception) {}
    }

    // -----------------------
    // Schema validation (simple properties/types)
    // -----------------------
    private fun validateResponseSchema(respBody: String?, schema: Schema<*>): List<String> {
        val errors = mutableListOf<String>()
        if (respBody.isNullOrBlank()) {
            errors.add("Empty response body, expected JSON per schema")
            return errors
        }
        try {
            val jsonNode = mapper.readTree(respBody)
            val props = schema.properties ?: return errors
            @Suppress("UNCHECKED_CAST")
            val propsMap = props as Map<String, Schema<Any>>
            propsMap.forEach { (field, propSchema) ->
                if (!jsonNode.has(field)) {
                    errors.add("Missing field: $field")
                } else {
                    val node = jsonNode.get(field)
                    val actualType = when {
                        node.isTextual -> "string"
                        node.isInt || node.isLong -> "integer"
                        node.isBoolean -> "boolean"
                        node.isDouble || node.isFloat -> "number"
                        node.isArray -> "array"
                        node.isObject -> "object"
                        else -> "unknown"
                    }
                    val expectedType = propSchema.type ?: when {
                        propSchema.`$ref` != null -> "object"
                        propSchema.format != null -> propSchema.format
                        else -> "string"
                    }
                    if (expectedType != actualType && !(expectedType == "number" && actualType == "integer")) {
                        errors.add("Field '$field' has type $actualType, expected $expectedType")
                    }
                }
            }
        } catch (e: Exception) {
            errors.add("Invalid JSON or schema validation error: ${e.message}")
        }
        return errors
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
                addIfNotDuplicate(issues, Issue("RATE_LIMITING", "$baseUrl/health", "GET", "MEDIUM", "Похоже, нет ограничителя запросов", "$success quick calls succeeded"))
            }
        } catch (_: Exception) {}

        val docPaths = listOf("/swagger-ui.html", "/swagger-ui/", "/docs", "/api-docs", "/swagger", "/redoc")
        for (p in docPaths) {
            try {
                val resp = client.get("$baseUrl$p")
                if (resp.status.value in 200..299) {
                    addIfNotDuplicate(issues, Issue("SECURITY_MISCONFIGURATION", "$baseUrl$p", "GET", "MEDIUM", "Документация / Swagger UI доступна публично", "HTTP ${resp.status.value}"))
                }
            } catch (_: Exception) {}
        }

        val sensitive = listOf("/.env", "/.git/config", "/.gitignore", "/.htpasswd")
        for (p in sensitive) {
            try {
                val resp = client.request("$baseUrl$p") { method = HttpMethod.Head }
                if (resp.status.value in 200..299) {
                    addIfNotDuplicate(issues, Issue("IMPROPER_ASSETS", "$baseUrl$p", "HEAD", "HIGH", "Чувствительный файл доступен по HTTP", "HTTP ${resp.status.value}"))
                }
            } catch (_: Exception) {}
        }

        try {
            val resp = client.get("$baseUrl/nonexistent_endpoint_for_logging_test_12345")
            val body = safeBodyText(resp)
            if (body.contains("Exception", true) || body.contains("StackTrace", true) || body.contains("at ")) {
                addIfNotDuplicate(issues, Issue("INSUFFICIENT_LOGGING", "$baseUrl/nonexistent_endpoint_for_logging_test_12345", "GET", "MEDIUM", "Сервер возвращает подробные ошибки/стек-трейс в теле ответа", body.take(1000)))
            }
        } catch (_: Exception) {}
    }

    // -----------------------
    // Утилиты
    // -----------------------
    private fun addIfNotDuplicate(list: MutableList<Issue>, issue: Issue) {
        val exists = list.any { it.type == issue.type && it.path == issue.path && it.method == issue.method }
        if (!exists) list.add(issue)
    }

    private fun addNetworkIssue(list: MutableList<Issue>, path: String, method: String, desc: String, evidence: String) {
        val issue = Issue("NETWORK_OR_CONFIGURATION", path, method, "LOW", desc, evidence)
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

    private fun extractOperations(pathItem: PathItem): Map<String, Operation?> {
        val map = mutableMapOf<String, Operation?>()
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

    private suspend fun checkTargetReachable(baseUrl: String, paths: Set<String>, issues: MutableList<Issue>): Boolean {
        // Try HEAD on base
        try {
            val resp = client.request(baseUrl) { method = HttpMethod.Head }
            val code = resp.status.value
            if (code in 200..399) return true
            if (code == 405) {
                // HEAD not allowed — try GET on first path if available
                if (paths.isNotEmpty()) {
                    val firstPath = paths.first()
                    val testUrl = if (baseUrl.endsWith("/")) baseUrl.dropLast(1) + firstPath else baseUrl + firstPath
                    try {
                        val respGet = client.get(testUrl)
                        if (respGet.status.value in 200..399) return true
                        addNetworkIssue(issues, testUrl, "GET", "Проверка GET на первый путь вернула HTTP ${respGet.status.value}", "HTTP ${respGet.status.value}")
                        return false
                    } catch (e: Exception) {
                        addNetworkIssue(issues, testUrl, "GET", "Ошибка при GET-проверке первого эндпоинта", e.message ?: "unknown")
                        return false
                    }
                } else {
                    addNetworkIssue(issues, baseUrl, "HEAD", "HEAD вернул 405 и в spec нет путей для проверки GET", "HTTP 405")
                    return false
                }
            } else {
                addNetworkIssue(issues, baseUrl, "HEAD", "Базовый URL ответил кодом $code — возможно неверный base path или конфигурация сервера", "HTTP $code")
                return false
            }
        } catch (e: Exception) {
            addNetworkIssue(issues, baseUrl, "HEAD", "Не удалось подключиться к базовому URL — проверьте host/путь/сетевые настройки", e.message ?: "unknown")
            return false
        }
    }
}
