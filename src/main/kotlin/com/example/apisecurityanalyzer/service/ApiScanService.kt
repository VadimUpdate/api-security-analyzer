package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.ScanReport
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.PathItem
import io.swagger.v3.oas.models.Operation
import io.swagger.v3.oas.models.parameters.Parameter
import io.swagger.v3.oas.models.media.Schema
import io.swagger.v3.parser.OpenAPIV3Parser
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Instant

@Service
class ApiScanService {

    private val log = LoggerFactory.getLogger(javaClass)
    private val mapper = jacksonObjectMapper()

    private val client = HttpClient(CIO) {
        install(HttpTimeout) {
            requestTimeoutMillis = 8000
            connectTimeoutMillis = 5000
            socketTimeoutMillis = 8000
        }
        defaultRequest {
            header("User-Agent", "ApiSecurityAnalyzer/1.0")
            header("X-Scanner", "true")
        }
    }

    @Volatile
    private var authToken: String? = null
    private val tokenMutex = Mutex()

    fun runScan(
        specUrl: String,
        targetUrl: String,
        maxConcurrency: Int = 4,
        politenessDelayMs: Int = 150,
        authClientId: String,
        authClientSecret: String
    ): ScanReport = runBlocking {
        val issues = mutableListOf<Issue>()

        // 1) Загрузка спецификации
        val specText = try {
            client.get(specUrl).bodyAsText()
        } catch (e: Exception) {
            issues.add(Issue("SPEC_LOAD_ERROR", specUrl, "GET", "HIGH", "Не удалось загрузить спецификацию", e.message ?: "unknown"))
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        // 2) Parse OpenAPI
        val openApi = try {
            val result = OpenAPIV3Parser().readContents(specText, null, null)
            result.openAPI ?: throw IllegalStateException("parser returned null openAPI")
        } catch (e: Exception) {
            issues.add(Issue("SPEC_PARSE_ERROR", specUrl, "PARSE", "HIGH", "Ошибка парсинга OpenAPI", e.message ?: "unknown"))
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        val pathsMap = openApi.paths ?: emptyMap()
        val totalEndpoints = pathsMap.entries.sumOf { extractOperations(it.value).size }

        // 3) Получение токена
        authToken = obtainBearerTokenFromSpecOrFallback(openApi, targetUrl, authClientId, authClientSecret, issues)
        if (authToken.isNullOrBlank()) {
            addNetworkIssue(issues, targetUrl, "POST", "Не удалось получить токен", "token=null")
        }

        // 4) Проверка доступности базового URL
        val reachable = checkTargetReachable(targetUrl, pathsMap.keys, issues, authClientId, authClientSecret)
        if (!reachable) return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())

        // 5) Параллельный обход эндпоинтов
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
                            runChecksForPath(testUrl, method, operation, issues, authClientId, authClientSecret)
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
        runGlobalChecks(targetUrl, issues, authClientId, authClientSecret)

        return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())
    }

    // -----------------------
    // --- Утилиты ---
    // -----------------------
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

    private fun buildUrlFromPath(base: String, pathTemplate: String, parameters: List<Parameter>? = null): String {
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
        val baseNormalized = base.removeSuffix("/")
        val pathNormalized = if (!url.startsWith("/")) "/$url" else url
        return baseNormalized + pathNormalized
    }

    private suspend fun safeBodyText(resp: HttpResponse): String = try { resp.bodyAsText() } catch (_: Exception) { "" }

    private fun addIfNotDuplicate(list: MutableList<Issue>, issue: Issue) {
        val exists = list.any { it.type == issue.type && it.path == issue.path && it.method == issue.method }
        if (!exists) list.add(issue)
    }

    private fun addNetworkIssue(list: MutableList<Issue>, path: String, method: String, desc: String, evidence: String) {
        val issue = Issue("NETWORK_OR_CONFIGURATION", path, method, "LOW", desc, evidence)
        addIfNotDuplicate(list, issue)
    }

    // -----------------------
    // --- Token & Auth ---
    // -----------------------
    private suspend fun obtainBearerTokenFromSpecOrFallback(
        openApi: io.swagger.v3.oas.models.OpenAPI?,
        baseUrlCandidate: String,
        clientId: String,
        clientSecret: String,
        issues: MutableList<Issue>
    ): String? {
        val candidates = mutableListOf<String>()
        try {
            if (openApi != null) {
                openApi.paths?.keys?.forEach { p ->
                    val lower = p.lowercase()
                    if ("token" in lower || "auth" in lower || "login" in lower) candidates.add(p)
                }
            }
        } catch (_: Exception) {}
        candidates.addAll(listOf("/auth/bank-token", "/oauth/token", "/auth/token", "/auth/login", "/token"))

        for (p in candidates) {
            val url = if (p.startsWith("http")) p else baseUrlCandidate.removeSuffix("/") + if (!p.startsWith("/")) "/$p" else p

            // Bank-token specific
            if (url.contains("/auth/bank-token")) {
                try {
                    val qClient = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name())
                    val qSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8.name())
                    val fullUrl = "$url?client_id=$qClient&client_secret=$qSecret"
                    val resp = client.post(fullUrl)
                    val bodyText = safeBodyText(resp)
                    if (resp.status.value in 200..299) {
                        val node = mapper.readTree(bodyText)
                        val token = node.get("access_token")?.asText() ?: node.get("token")?.asText()
                        if (!token.isNullOrBlank()) return token
                    } else addNetworkIssue(issues, fullUrl, "POST", "Token endpoint returned HTTP ${resp.status.value}", bodyText.take(500))
                } catch (_: Exception) {}
                continue
            }

            // Fallback form-urlencoded
            try {
                val resp = client.post(url) {
                    contentType(ContentType.Application.FormUrlEncoded)
                    setBody(FormDataContent(Parameters.build {
                        append("grant_type", "client_credentials")
                        append("client_id", clientId)
                        append("client_secret", clientSecret)
                    }))
                }
                val bodyText = safeBodyText(resp)
                if (resp.status.value in 200..299) {
                    val node = mapper.readTree(bodyText)
                    val token = node.get("access_token")?.asText() ?: node.get("token")?.asText()
                    if (!token.isNullOrBlank()) return token
                } else addNetworkIssue(issues, url, "POST", "Token endpoint returned HTTP ${resp.status.value}", bodyText.take(500))
            } catch (_: Exception) {}

            // Fallback JSON
            try {
                val resp = client.post(url) {
                    contentType(ContentType.Application.Json)
                    setBody(mapOf("grant_type" to "client_credentials", "client_id" to clientId, "client_secret" to clientSecret))
                }
                val bodyText = safeBodyText(resp)
                if (resp.status.value in 200..299) {
                    val node = mapper.readTree(bodyText)
                    val token = node.get("access_token")?.asText() ?: node.get("token")?.asText()
                    if (!token.isNullOrBlank()) return token
                } else addNetworkIssue(issues, url, "POST", "Token endpoint returned HTTP ${resp.status.value}", bodyText.take(500))
            } catch (_: Exception) {}
        }

        addNetworkIssue(issues, baseUrlCandidate, "POST", "Не удалось получить токен автоматически", "no-token")
        return null
    }

    private suspend fun performRequestWithAuth(method: HttpMethod, url: String, authClientId: String, authClientSecret: String, bodyBlock: (HttpRequestBuilder.() -> Unit)? = null, issues: MutableList<Issue>): HttpResponse {
        suspend fun doRequest(token: String?): HttpResponse {
            return client.request(url) {
                this.method = method
                token?.let { header("Authorization", "Bearer $it") }
                bodyBlock?.invoke(this)
            }
        }
        val current = authToken
        try {
            return doRequest(current)
        } catch (e: ResponseException) {
            val status = try { (e.response as? HttpResponse)?.status?.value } catch (_: Exception) { null }
            if (status == 401) {
                tokenMutex.withLock {
                    val newToken = obtainBearerTokenFromSpecOrFallback(null, url, authClientId, authClientSecret, issues)
                    if (!newToken.isNullOrBlank()) authToken = newToken
                }
                return doRequest(authToken)
            } else throw e
        }
    }

    // -----------------------
    // --- Checks per path ---
    // -----------------------
    private suspend fun runChecksForPath(testUrl: String, method: String, operation: Operation, issues: MutableList<Issue>, authClientId: String, authClientSecret: String) {
        suspend fun doWithAuthRetry(block: suspend (String?) -> HttpResponse): HttpResponse {
            val current = authToken
            try {
                return block(current)
            } catch (e: ResponseException) {
                val status = try { (e.response as? HttpResponse)?.status?.value } catch (_: Exception) { null }
                if (status == 401) {
                    tokenMutex.withLock {
                        val newToken = obtainBearerTokenFromSpecOrFallback(null, testUrl, authClientId, authClientSecret, issues)
                        if (!newToken.isNullOrBlank()) authToken = newToken
                    }
                    return block(authToken)
                } else throw e
            }
        }

        // GET checks
        if (method.equals("GET", true)) {
            try {
                val resp = doWithAuthRetry { token -> client.get(testUrl) { token?.let { header("Authorization", "Bearer $it") } } }
                val code = resp.status.value
                val body = safeBodyText(resp)

                // Schema validation
                val responseSpec = operation.responses?.get("200") ?: operation.responses?.get("201") ?: operation.responses?.get("default") ?: operation.responses?.values?.firstOrNull()
                responseSpec?.content?.get("application/json")?.schema?.let { schema ->
                    validateResponseSchema(body, schema).forEach { err ->
                        addIfNotDuplicate(issues, Issue("SCHEMA_MISMATCH", testUrl, method, "MEDIUM", err, body.take(500)))
                    }
                }

                // Sensitive fields
                if (containsSensitiveField(body)) addIfNotDuplicate(issues, Issue("EXCESSIVE_DATA_EXPOSURE", testUrl, method, "HIGH", "Ответ содержит чувствительные поля", body.take(1000)))

                // BOLA
                if (Regex("/\\d+").containsMatchIn(testUrl) || testUrl.endsWith("/1")) addIfNotDuplicate(issues, Issue("BOLA", testUrl, method, "MEDIUM", "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA", "HTTP $code"))

                // IDOR
                checkIDOR(testUrl, method, issues, authClientId, authClientSecret)

                // Broken Auth
                val requiresAuth = (operation.security != null && operation.security.isNotEmpty()) || (operation.responses?.keys?.contains("401") == true)
                if (requiresAuth) checkBrokenAuth(testUrl, method, issues, authClientId, authClientSecret)
            } catch (e: Exception) {
                addNetworkIssue(issues, testUrl, "GET", "Ошибка сети при GET", e.message ?: "unknown")
            }
        }

        // POST Mass Assignment
        if (method.equals("POST", true) && operation.requestBody != null) {
            try {
                val resp = doWithAuthRetry { token ->
                    client.post(testUrl) {
                        contentType(ContentType.Application.Json)
                        header("X-Scanner-Probe", "true")
                        token?.let { header("Authorization", "Bearer $it") }
                        setBody("""{"__scanner_probe":true,"role":"admin","isAdmin":true}""")
                    }
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

        // Injection probe
        try {
            val injUrl = if (testUrl.contains("?")) "$testUrl&debug=' OR '1'='1" else "$testUrl?debug=' OR '1'='1"
            val resp = doWithAuthRetry { token ->
                client.get(injUrl) { token?.let { header("Authorization", "Bearer $it") } }
            }
            if (resp.status.value in 200..299) {
                val body = safeBodyText(resp)
                if (body.contains("syntax", true) || body.contains("sql", true) || body.contains("exception", true))
                    addIfNotDuplicate(issues, Issue("INJECTION", injUrl, "GET", "HIGH", "Потенциальная инъекция", body.take(1000)))
            }
        } catch (e: Exception) {
            addNetworkIssue(issues, testUrl, "GET", "Ошибка сети при injection probe", e.message ?: "unknown")
        }
    }

    // -----------------------
    // --- Checks: IDOR / Auth ---
    // -----------------------
    private suspend fun checkIDOR(testUrl: String, method: String, issues: MutableList<Issue>, authClientId: String, authClientSecret: String) {
        if (!method.equals("GET", true)) return
        val alteredUrl = testUrl.replace(Regex("/\\d+")) { "/999999" }
        if (alteredUrl == testUrl) return
        try {
            val resp = performRequestWithAuth(HttpMethod.Get, alteredUrl, authClientId, authClientSecret, null, issues)
            if (resp.status.value in 200..299) addIfNotDuplicate(issues, Issue("IDOR", alteredUrl, "GET", "HIGH", "Публичный доступ к чужому ресурсу (IDOR)", "HTTP ${resp.status.value}"))
        } catch (_: Exception) {}
    }

    private suspend fun checkBrokenAuth(testUrl: String, method: String, issues: MutableList<Issue>, authClientId: String, authClientSecret: String) {
        try {
            val resp = performRequestWithAuth(HttpMethod.Get, testUrl, authClientId, authClientSecret, null, issues)
            if (resp.status.value in 200..299) addIfNotDuplicate(issues, Issue("BROKEN_AUTH", testUrl, method, "HIGH", "Эндпоинт доступен без аутентификации", "HTTP ${resp.status.value}"))
        } catch (_: Exception) {}
    }

    // -----------------------
    // --- Global Checks ---
    // -----------------------
    private suspend fun runGlobalChecks(baseUrl: String, issues: MutableList<Issue>, authClientId: String, authClientSecret: String) {
        try {
            var success = 0
            repeat(6) {
                val resp = performRequestWithAuth(HttpMethod.Get, "$baseUrl/health", authClientId, authClientSecret, null, issues)
                if (resp.status.value in 200..299) success++
            }
            if (success >= 5) addIfNotDuplicate(issues, Issue("RATE_LIMITING", "$baseUrl/health", "GET", "MEDIUM", "Похоже, нет ограничителя запросов", "$success quick calls succeeded"))
        } catch (_: Exception) {}

        val docPaths = listOf("/swagger-ui.html", "/swagger-ui/", "/docs", "/api-docs", "/swagger", "/redoc")
        for (p in docPaths) {
            try {
                val resp = performRequestWithAuth(HttpMethod.Get, "$baseUrl$p", authClientId, authClientSecret, null, issues)
                if (resp.status.value in 200..299) addIfNotDuplicate(issues, Issue("SECURITY_MISCONFIGURATION", "$baseUrl$p", "GET", "MEDIUM", "Документация / Swagger UI доступна публично", "HTTP ${resp.status.value}"))
            } catch (_: Exception) {}
        }
    }

    // -----------------------
    // --- Target Reachable ---
    // -----------------------
    private suspend fun checkTargetReachable(baseUrl: String, paths: Set<String>, issues: MutableList<Issue>, authClientId: String, authClientSecret: String): Boolean {
        try {
            val resp = performRequestWithAuth(HttpMethod.Head, baseUrl, authClientId, authClientSecret, null, issues)
            val code = resp.status.value
            if (code in 200..399) return true
            if (code == 405 && paths.isNotEmpty()) {
                val firstPath = paths.first()
                val testUrl = if (baseUrl.endsWith("/")) baseUrl.dropLast(1) + firstPath else baseUrl + firstPath
                val respGet = performRequestWithAuth(HttpMethod.Get, testUrl, authClientId, authClientSecret, null, issues)
                if (respGet.status.value in 200..399) return true
                addNetworkIssue(issues, testUrl, "GET", "Проверка GET на первый путь вернула HTTP ${respGet.status.value}", "HTTP ${respGet.status.value}")
                return false
            } else {
                addNetworkIssue(issues, baseUrl, "HEAD", "Базовый URL ответил кодом $code — возможно неверный base path или конфигурация сервера", "HTTP $code")
                return false
            }
        } catch (e: Exception) {
            addNetworkIssue(issues, baseUrl, "HEAD", "Не удалось подключиться к базовому URL", e.message ?: "unknown")
            return false
        }
    }

    // -----------------------
    // --- Schema validation ---
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
                if (!jsonNode.has(field)) errors.add("Missing field: $field")
                else {
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
                    val expectedType = propSchema.type ?: if (propSchema.`$ref` != null) "object" else propSchema.format ?: "string"
                    if (expectedType != actualType && !(expectedType == "number" && actualType == "integer"))
                        errors.add("Field '$field' has type $actualType, expected $expectedType")
                }
            }
        } catch (e: Exception) { errors.add("Invalid JSON or schema validation error: ${e.message}") }
        return errors
    }

    private fun containsSensitiveField(body: String?): Boolean {
        if (body == null) return false
        val keys = listOf("password", "ssn", "creditCard", "cardNumber", "cvv", "secret", "token", "access_token")
        return keys.any { body.contains(it, ignoreCase = true) }
    }
}
