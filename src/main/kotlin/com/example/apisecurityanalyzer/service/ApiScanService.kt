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
import io.ktor.client.request.setBody
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
import kotlin.random.Random

@Service
class ApiScanService {

    private val log = LoggerFactory.getLogger(javaClass)
    private val mapper = jacksonObjectMapper()

    // Ktor client with reasonable defaults
    private val client = HttpClient(CIO) {
        install(HttpTimeout) {
            requestTimeoutMillis = 15_000
            connectTimeoutMillis = 10_000
            socketTimeoutMillis = 15_000
        }
        defaultRequest {
            header("User-Agent", "ApiSecurityAnalyzer/3.0")
            header("X-Scanner", "true")
        }
    }

    @Volatile
    private var authToken: String? = null
    private val tokenMutex = Mutex()

    /**
     * Main entry
     */
    fun runScan(
        specUrl: String,
        targetUrl: String,
        maxConcurrency: Int = 6,
        politenessDelayMs: Int = 150,
        authClientId: String = "",
        authClientSecret: String = ""
    ): ScanReport = runBlocking {
        val issues = mutableListOf<Issue>()

        // 1) load spec
        val specText = try {
            client.get(specUrl).bodyAsText()
        } catch (e: Exception) {
            addIfNotDuplicate(issues, Issue("SPEC_LOAD_ERROR", specUrl, "GET", "HIGH", "Не удалось загрузить спецификацию", e.message ?: "unknown"))
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        // 2) parse openapi
        val openApi = try {
            val res = OpenAPIV3Parser().readContents(specText, null, null)
            res.openAPI ?: throw IllegalStateException("parser returned null openAPI")
        } catch (e: Exception) {
            addIfNotDuplicate(issues, Issue("SPEC_PARSE_ERROR", specUrl, "PARSE", "HIGH", "Ошибка парсинга спецификации", e.message ?: "unknown"))
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        val pathsMap = openApi.paths ?: emptyMap()

        // avoid ambiguous sumOf overload by explicit map+sum
        val totalEndpoints = pathsMap.entries.map { entry -> extractOperations(entry.value).size }.sum()

        // 3) obtain token (best-effort)
        if (authClientId.isNotBlank() && authClientSecret.isNotBlank()) {
            authToken = obtainBearerTokenFromSpecOrFallback(openApi, targetUrl, authClientId, authClientSecret, issues)
            if (authToken.isNullOrBlank()) addNetworkIssue(issues, targetUrl, "POST", "Не удалось получить токен автоматически", "token=null")
        }

        // 4) check reachable
        val reachable = checkTargetReachable(targetUrl, pathsMap.keys, issues, authClientId, authClientSecret)
        if (!reachable) return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())

        // 5) parallel scanning
        val semaphore = Semaphore(maxConcurrency)
        val jobs = mutableListOf<Deferred<Unit>>()

        for ((pathTemplate, pathItem) in pathsMap) {
            val operations = extractOperations(pathItem)
            for ((method, operation) in operations) {
                if (operation == null) continue
                val combinedParams = (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())
                val testUrl = buildUrlFromPath(targetUrl, pathTemplate, combinedParams)
                val op = operation

                val job = async {
                    semaphore.withPermit {
                        delay(politenessDelayMs.toLong())
                        try {
                            runAllChecksForPath(testUrl, method, op, issues, authClientId, authClientSecret)
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

        // 6) Global checks
        runGlobalChecks(targetUrl, issues, authClientId, authClientSecret)

        return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())
    }

    // -----------------------
    // Per-path aggregated checks
    // -----------------------
    private suspend fun runAllChecksForPath(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>,
        authClientId: String,
        authClientSecret: String
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

        // GET/HEAD
        if (method.equals("GET", true) || method.equals("HEAD", true)) {
            try {
                val resp = performRequestWithAuth(HttpMethod.Get, url, authClientId, authClientSecret, null, issues)
                val code = resp.status.value
                val body = safeBodyText(resp)

                if (code !in 200..399) {
                    addIfNotDuplicate(issues, Issue("ENDPOINT_ERROR_STATUS", url, method, if (code >= 500) "HIGH" else "LOW", "Эндпоинт вернул HTTP $code", "HTTP $code"))
                } else {
                    // response validation
                    val responseSpec = operation.responses?.get("200") ?: operation.responses?.get("201") ?: operation.responses?.get("default") ?: operation.responses?.values?.firstOrNull()
                    responseSpec?.content?.get("application/json")?.schema?.let { schema ->
                        validateResponseSchema(body, schema).forEach { err ->
                            addIfNotDuplicate(issues, Issue("SCHEMA_MISMATCH", url, method, "MEDIUM", err, body.take(500)))
                        }
                    }

                    // BOLA heuristic
                    if (Regex("/\\d+").containsMatchIn(url) || url.endsWith("/1")) {
                        addIfNotDuplicate(issues, Issue("BOLA", url, method, "MEDIUM", "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA", "HTTP $code"))
                    }

                    // Excessive data exposure
                    if (containsSensitiveField(body)) {
                        addIfNotDuplicate(issues, Issue("EXCESSIVE_DATA_EXPOSURE", url, method, "HIGH", "Ответ содержит возможные чувствительные поля", body.take(1000)))
                    }
                }

                // IDOR and Broken Auth checks
                checkIDOR(url, method, issues, authClientId, authClientSecret)
                val requiresAuth = (operation.security != null && operation.security.isNotEmpty()) || (operation.responses?.keys?.contains("401") == true)
                if (requiresAuth) checkBrokenAuth(url, method, issues, authClientId, authClientSecret)

            } catch (e: Exception) {
                addNetworkIssue(issues, url, method, "Ошибка сети при GET/HEAD", e.message ?: "unknown")
            }
        }

        // POST/PUT/PATCH (mass assignment, request validation, injection)
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
                    val httpMethod = methodFromString(method)
                    val resp = performRequestWithAuth(httpMethod, url, authClientId, authClientSecret, {
                        contentType(ContentType.Application.Json)
                        this.setBody(body)
                        header("X-Scanner-Probe", "true")
                    }, issues)

                    val code = resp.status.value
                    val respBody = safeBodyText(resp)

                    // mass assignment heuristic
                    if ((method.equals("POST", true) || method.equals("PUT", true)) && code in 200..299) {
                        if (!respBody.contains("error", true) && !respBody.contains("validation", true) &&
                            (body.contains("isAdmin") || body.contains("role"))
                        ) {
                            addIfNotDuplicate(issues, Issue("MASS_ASSIGNMENT", url, method, "MEDIUM", "POST/PUT принял дополнительные/административные поля", "HTTP $code, body: ${respBody.take(500)}"))
                        }
                    }

                    // request contract validation
                    operation.requestBody?.content?.get("application/json")?.schema?.let { schema ->
                        validateRequestBody(body, schema).forEach { err ->
                            addIfNotDuplicate(issues, Issue("REQUEST_SCHEMA_MISMATCH", url, method, "MEDIUM", err, body.take(500)))
                        }
                    }

                    // insufficient logging
                    if (respBody.contains("Exception", true) || respBody.contains("StackTrace", true) || respBody.contains("java.lang", true)) {
                        addIfNotDuplicate(issues, Issue("INSUFFICIENT_LOGGING", url, method, "MEDIUM", "Сервер возвращает подробные ошибки/стек-трейс", respBody.take(1000)))
                    }

                    // injection detection heuristic
                    if ((body.contains("' OR '1'='1") || body.contains("<script") || body.contains("..\\")) &&
                        (respBody.contains("syntax", true) || respBody.contains("sql", true) || respBody.contains("exception", true))
                    ) {
                        addIfNotDuplicate(issues, Issue("INJECTION", url, method, "HIGH", "Потенциальная инъекция при передаче тела", respBody.take(1000)))
                    }

                } catch (e: Exception) {
                    addNetworkIssue(issues, url, method, "Ошибка сети при POST/PUT/PATCH probe", e.message ?: "unknown")
                }
            }
        }

        // Function-level checks (/admin, /debug, /config...)
        val adminCandidates = listOf("/admin", "/debug", "/config", "/test", "/internal")
        for (suf in adminCandidates) {
            try {
                val adminUrl = url.trimEnd('/') + suf
                val resp = performRequestWithAuth(HttpMethod.Get, adminUrl, authClientId, authClientSecret, null, issues)
                if (resp.status.value in 200..299) {
                    addIfNotDuplicate(issues, Issue("BROKEN_FUNCTION_LEVEL_AUTH", adminUrl, "GET", "HIGH", "Административный/debug эндпоинт доступен публично", "HTTP ${resp.status.value}"))
                }
            } catch (_: Exception) {}
        }

        // quick injection via query param
        try {
            val injUrl = if (url.contains("?")) "$url&__scan_inj=' OR '1'='1" else "$url?__scan_inj=' OR '1'='1"
            val resp = performRequestWithAuth(HttpMethod.Get, injUrl, authClientId, authClientSecret, null, issues)
            if (resp.status.value in 200..299) {
                val b = safeBodyText(resp)
                if (b.contains("sql", true) || b.contains("syntax", true) || b.contains("exception", true)) {
                    addIfNotDuplicate(issues, Issue("INJECTION", injUrl, "GET", "HIGH", "Потенциальная инъекция через query param", b.take(1000)))
                }
            }
        } catch (_: Exception) {}
    }

    // -----------------------
    // perform request with auth + retry on 401
    // -----------------------
    private suspend fun performRequestWithAuth(
        method: HttpMethod,
        url: String,
        authClientId: String,
        authClientSecret: String,
        bodyBlock: (HttpRequestBuilder.() -> Unit)? = null,
        issues: MutableList<Issue>
    ): HttpResponse {
        suspend fun doRequest(token: String?): HttpResponse {
            return client.request(url) {
                this.method = method
                token?.let { header("Authorization", "Bearer $it") }
                bodyBlock?.invoke(this)
            }
        }

        val cur = authToken
        try {
            return doRequest(cur)
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
    // obtain bearer token best-effort
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

            // special bank-token
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

            // form encoded
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

            // json
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

    // -----------------------
    // IDOR & Broken Auth
    // -----------------------
    private suspend fun checkIDOR(url: String, method: String, issues: MutableList<Issue>, authClientId: String, authClientSecret: String) {
        if (!method.equals("GET", true)) return
        val altered = url.replace(Regex("/\\d+")) { "/999999999" }
        if (altered == url) return
        try {
            val resp = performRequestWithAuth(HttpMethod.Get, altered, authClientId, authClientSecret, null, issues)
            if (resp.status.value in 200..299) addIfNotDuplicate(issues, Issue("IDOR", altered, "GET", "HIGH", "Доступ к чужому ресурсу (IDOR)", "HTTP ${resp.status.value}"))
        } catch (_: Exception) {}
    }

    private suspend fun checkBrokenAuth(url: String, method: String, issues: MutableList<Issue>, authClientId: String, authClientSecret: String) {
        try {
            val resp = client.get(url) { /* intentionally without Authorization */ }
            if (resp.status.value in 200..299) addIfNotDuplicate(issues, Issue("BROKEN_AUTH", url, method, "HIGH", "Эндпоинт доступен без аутентификации", "HTTP ${resp.status.value}"))
        } catch (_: Exception) {}
    }

    // -----------------------
    // Global checks
    // -----------------------
    private suspend fun runGlobalChecks(baseUrl: String, issues: MutableList<Issue>, authClientId: String, authClientSecret: String) {
        try {
            var success = 0
            repeat(6) {
                try {
                    val resp = performRequestWithAuth(HttpMethod.Get, "$baseUrl/health", authClientId, authClientSecret, null, issues)
                    if (resp.status.value in 200..299) success++
                } catch (_: Exception) {}
            }
            if (success >= 5) addIfNotDuplicate(issues, Issue("RATE_LIMITING", "$baseUrl/health", "GET", "MEDIUM", "Похоже, нет ограничителя запросов", "$success quick calls succeeded"))
        } catch (_: Exception) {}

        val docPaths = listOf("/swagger-ui.html", "/swagger-ui/", "/docs", "/api-docs", "/swagger", "/redoc")
        for (p in docPaths) {
            try {
                val resp = performRequestWithAuth(HttpMethod.Get, "$baseUrl$p", authClientId, authClientSecret, null, issues)
                if (resp.status.value in 200..299) addIfNotDuplicate(issues, Issue("SECURITY_MISCONFIGURATION", "$baseUrl$p", "GET", "MEDIUM", "Документация доступна публично", "HTTP ${resp.status.value}"))
            } catch (_: Exception) {}
        }

        val sensitive = listOf("/.env", "/.git/config", "/.gitignore", "/.htpasswd", "/backup.zip", "/config.yml")
        for (p in sensitive) {
            try {
                val resp = client.request("$baseUrl$p") { method = HttpMethod.Head }
                if (resp.status.value in 200..299) addIfNotDuplicate(issues, Issue("IMPROPER_ASSETS", "$baseUrl$p", "HEAD", "HIGH", "Чувствительный файл доступен по HTTP", "HTTP ${resp.status.value}"))
            } catch (_: Exception) {}
        }

        try {
            val resp = client.get("$baseUrl/nonexistent_endpoint_for_logging_test_12345")
            val b = safeBodyText(resp)
            if (b.contains("Exception", true) || b.contains("StackTrace", true) || b.contains("java.lang", true)) {
                addIfNotDuplicate(issues, Issue("INSUFFICIENT_LOGGING", "$baseUrl/nonexistent_endpoint_for_logging_test_12345", "GET", "MEDIUM", "Сервер возвращает подробные ошибки/стек-трейс в теле ответа", b.take(1000)))
            }
        } catch (_: Exception) {}

        val fuzzTargets = listOf("$baseUrl/", "$baseUrl/health")
        val fuzzPayloads = generateFuzzPayloads()
        for (t in fuzzTargets) {
            for (p in fuzzPayloads.take(5)) {
                try {
                    val resp = client.post(t) {
                        contentType(ContentType.Application.Json)
                        setBody(p)
                    }
                    val b = safeBodyText(resp)
                    if (resp.status.value >= 500 || b.contains("Exception", true) || b.contains("StackTrace", true)) {
                        addIfNotDuplicate(issues, Issue("FUZZ_CRASH", t, "POST", "HIGH", "Fuzzing вызвал ошибку/падение", "HTTP ${resp.status.value}, body: ${b.take(500)}"))
                    }
                } catch (_: Exception) {}
            }
        }
    }

    // -----------------------
    // Schema & contract helpers
    // -----------------------
    private fun validateResponseSchema(respBody: String?, schema: Schema<*>): List<String> {
        val errors = mutableListOf<String>()
        if (respBody.isNullOrBlank()) {
            errors.add("Empty response body, expected JSON per schema")
            return errors
        }
        try {
            val node = mapper.readTree(respBody)
            val props = schema.properties ?: return errors
            @Suppress("UNCHECKED_CAST")
            val propsMap = props as Map<String, Schema<Any>>
            propsMap.forEach { (field, propSchema) ->
                if (!node.has(field)) errors.add("Missing field: $field")
                else {
                    val n = node.get(field)
                    val actualType = when {
                        n.isTextual -> "string"
                        n.isInt || n.isLong -> "integer"
                        n.isBoolean -> "boolean"
                        n.isDouble || n.isFloat -> "number"
                        n.isArray -> "array"
                        n.isObject -> "object"
                        else -> "unknown"
                    }
                    val expectedType = propSchema.type ?: if (propSchema.`$ref` != null) "object" else propSchema.format ?: "string"
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

    private fun validateRequestBody(bodyJson: String, schema: Schema<*>): List<String> {
        val errors = mutableListOf<String>()
        try {
            val node = mapper.readTree(bodyJson)
            val required = schema.required ?: emptyList()
            required.forEach { req ->
                if (!node.has(req)) errors.add("Missing required request field: $req")
            }
        } catch (e: Exception) {
            errors.add("Invalid JSON request body: ${e.message}")
        }
        return errors
    }

    private fun buildSampleJsonFromSchema(schema: Schema<*>): String {
        val map = mutableMapOf<String, Any?>()
        try {
            val props = schema.properties ?: return "{}"
            @Suppress("UNCHECKED_CAST")
            val propsMap = props as Map<String, Schema<Any>>
            propsMap.forEach { (name, s) ->
                val t = s.type ?: if (s.`$ref` != null) "object" else "string"
                val example = when (t) {
                    "integer" -> 1
                    "number" -> 1
                    "boolean" -> true
                    "array" -> listOf<Any>()
                    "object" -> mapOf<String, Any?>()
                    else -> s.example ?: "test"
                }
                map[name] = example
            }
        } catch (_: Exception) {}
        return try { mapper.writeValueAsString(map) } catch (_: Exception) { "{}" }
    }

    private fun generateFuzzPayloads(): Sequence<String> = sequence {
        val payloads = listOf(
            "{ \"a\": \"${"A".repeat(2000)}\" }",
            "{ \"a\": \"' OR '1'='1\" }",
            "{ \"a\": \"<script>alert(1)</script>\" }",
            "{ \"a\": \"..\\\\..\\\\..\\\\Windows\\\\system32\" }",
            "{ \"a\": ${Int.MAX_VALUE} }",
            "{ \"a\": null }"
        )
        for (p in payloads) yield(p)
        repeat(5) {
            val r = Random.nextBytes(64).joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
            yield("{\"rand\":\"$r\"}")
        }
    }

    // -----------------------
    // Utilities: extractOperations, buildUrlFromPath, helpers
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
                p.example != null -> p.example.toString()
                p.schema?.type == "integer" -> "1"
                p.schema?.type == "number" -> "1"
                p.schema?.type == "boolean" -> "true"
                p.schema?.type == "string" -> "test"
                else -> "test"
            }
            val encoded = try { URLEncoder.encode(example, StandardCharsets.UTF_8.name()) } catch (_: Exception) { example }
            url = url.replace("{$name}", encoded)
        }

        url = url.replace(Regex("\\{[^}]+\\}"), "test")

        val baseNormalized = base.removeSuffix("/")
        val pathNormalized = if (!url.startsWith("/")) "/$url" else url
        return baseNormalized + pathNormalized
    }

    private fun addIfNotDuplicate(list: MutableList<Issue>, issue: Issue) {
        val exists = list.any { it.type == issue.type && it.path == issue.path && it.method == issue.method && it.description == issue.description }
        if (!exists) list.add(issue)
    }

    private fun addNetworkIssue(list: MutableList<Issue>, path: String, method: String, desc: String, evidence: String) {
        val issue = Issue("NETWORK_OR_CONFIGURATION", path, method, "LOW", desc, evidence)
        addIfNotDuplicate(list, issue)
    }

    private fun containsSensitiveField(body: String?): Boolean {
        if (body == null) return false
        val keys = listOf("password", "ssn", "creditCard", "cardNumber", "cvv", "secret", "token", "access_token", "privateKey")
        return keys.any { body.contains(it, ignoreCase = true) }
    }

    private suspend fun safeBodyText(resp: HttpResponse): String {
        return try { resp.bodyAsText() } catch (e: Exception) { "" }
    }

    private suspend fun checkTargetReachable(
        baseUrl: String,
        paths: Set<String>,
        issues: MutableList<Issue>,
        authClientId: String,
        authClientSecret: String
    ): Boolean {
        try {
            val resp = performRequestWithAuth(HttpMethod.Head, baseUrl, authClientId, authClientSecret, null, issues)
            val code = resp.status.value
            if (code in 200..399) return true

            // Если HEAD вернул 405 — часто означает: HEAD/GET не разрешены, но сервис жив (например, token endpoints)
            if (code == 405) {
                // Если в пути (или в spec) есть token/auth/login — попробуем POST получить токен (best-effort)
                val tokenPaths = paths.filter { it.contains("token", ignoreCase = true) || it.contains("auth", ignoreCase = true) || it.contains("login", ignoreCase = true) }
                if (tokenPaths.isNotEmpty()) {
                    // Попробуем POST на первый кандидатный путь (если клиентские креды есть)
                    val first = tokenPaths.first()
                    val testUrl = if (first.startsWith("http")) first else baseUrl.removeSuffix("/") + if (!first.startsWith("/")) "/$first" else first
                    // Если у нас есть clientId/secret — попробуем получить token
                    if (authClientId.isNotBlank() && authClientSecret.isNotBlank()) {
                        try {
                            // сначала form-urlencoded
                            val tokenResp = client.post(testUrl) {
                                contentType(ContentType.Application.FormUrlEncoded)
                                setBody(FormDataContent(Parameters.build {
                                    append("grant_type", "client_credentials")
                                    append("client_id", authClientId)
                                    append("client_secret", authClientSecret)
                                }))
                            }
                            val bodyText = safeBodyText(tokenResp)
                            if (tokenResp.status.value in 200..299) {
                                val node = mapper.readTree(bodyText)
                                val token = node.get("access_token")?.asText() ?: node.get("token")?.asText()
                                if (!token.isNullOrBlank()) {
                                    // получили токен — считаем endpoint reachable
                                    return true
                                }
                            }
                        } catch (_: Exception) {
                            // ignore — below we will add a LOW network issue if needed
                        }
                    }
                }

                // Если 405 и это путь токена — не считать это серьёзной ошибкой, просто не добавляем LOW issue.
                // Но если path не явно token-like, добавим network issue
                val firstPath = paths.firstOrNull() ?: ""
                if (firstPath.contains("token", ignoreCase = true) || firstPath.contains("auth", ignoreCase = true)) {
                    // treat as reachable (or at least not an error)
                    return true
                }

                // иначе — добавить запись и вернуть false
                addNetworkIssue(issues, baseUrl, "HEAD", "Базовый URL вернул 405 (HEAD not allowed)", "HTTP 405")
                return false
            }

            addNetworkIssue(issues, baseUrl, "HEAD", "Базовый URL ответил кодом $code — возможно неверный base path или конфигурация сервера", "HTTP $code")
            return false
        } catch (e: Exception) {
            addNetworkIssue(issues, baseUrl, "HEAD", "Не удалось подключиться к базовому URL — проверьте host/путь/сетевые настройки", e.message ?: "unknown")
            return false
        }
    }

}
