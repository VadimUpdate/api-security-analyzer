package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.ScanReport
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.Operation
import io.swagger.v3.oas.models.PathItem
import io.swagger.v3.parser.OpenAPIV3Parser
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.Instant

/**
 * Сервис-оркестратор сканирования.
 * Логика runScan и runAllChecksForPath полностью перенесена из монолита, без удаления поведения.
 */
@Service
class ApiScanService(
    private val clientProvider: ClientProvider = ClientProvider(),
    private val authService: AuthService = AuthService(clientProvider)
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val mapper = jacksonObjectMapper()
    private val client get() = clientProvider.client

    /**
     * Самая верхняя точка: синхронный runScan (оставлен runBlocking, как в оригинале).
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

        // 1) Load OpenAPI spec
        val specText = try { client.get(specUrl).bodyAsText() }
        catch (e: Exception) {
            addIfNotDuplicate(issues, Issue("SPEC_LOAD_ERROR", specUrl, "GET", "HIGH", "Не удалось загрузить спецификацию", e.message ?: "unknown"))
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        // 2) Parse spec
        val openApi = try {
            OpenAPIV3Parser().readContents(specText, null, null).openAPI
                ?: throw IllegalStateException("parser returned null openAPI")
        } catch (e: Exception) {
            addIfNotDuplicate(issues, Issue("SPEC_PARSE_ERROR", specUrl, "PARSE", "HIGH", "Ошибка парсинга спецификации", e.message ?: "unknown"))
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        val pathsMap = openApi.paths ?: emptyMap()
        val totalEndpoints = pathsMap.entries.map { extractOperations(it.value).size }.sum()

        // 3) Obtain token (best-effort) — если переданы client_id/secret
        if (authClientId.isNotBlank() && authClientSecret.isNotBlank()) {
            authService.authToken = authService.obtainBearerTokenFromSpecOrFallback(openApi, targetUrl, authClientId, authClientSecret, issues)
            if (authService.authToken.isNullOrBlank()) addNetworkIssue(issues, targetUrl, "POST", "Не удалось получить токен автоматически", "token=null")
        }

        // 4) Check reachable
        val reachable = checkTargetReachable(client, targetUrl, pathsMap.keys, issues)
        if (!reachable) return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())

        // 5) Parallel scanning
        val semaphore = Semaphore(maxConcurrency)

        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()

            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)
                for ((method, operation) in operations) {
                    if (operation == null) continue
                    val combinedParams = (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())
                    val testUrl = buildUrlFromPath(targetUrl, pathTemplate, combinedParams)
                    val op = operation

                    val job = async<Unit> {
                        semaphore.withPermit {
                            delay(politenessDelayMs.toLong())
                            try {
                                runAllChecksForPath(testUrl, method, op, issues, openApi, authClientId, authClientSecret)
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
        } // end coroutineScope

        // 6) Global checks (public docs)
        runGlobalChecks(client, targetUrl, issues)

        ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())
    }

    // -----------------------
    // Per-path checks including contract validation
    // -----------------------
    private suspend fun runAllChecksForPath(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>,
        openApi: OpenAPI,
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

        // -----------------------
        // GET / HEAD
        // -----------------------
        if (method.equals("GET", true) || method.equals("HEAD", true)) {
            try {
                val resp = authService.performRequestWithAuth(HttpMethod.Get, url, authClientId, authClientSecret, null, issues)
                val code = resp.status.value
                val body = safeBodyText(resp)

                if (code !in 200..399) {
                    addIfNotDuplicate(issues, Issue("ENDPOINT_ERROR_STATUS", url, method, if (code >= 500) "HIGH" else "LOW", "Эндпоинт вернул HTTP $code", "HTTP $code"))
                } else {
                    // Contract validation (response)
                    val responseSpec = operation.responses?.get("200")
                        ?: operation.responses?.get("201")
                        ?: operation.responses?.get("default")
                        ?: operation.responses?.values?.firstOrNull()
                    responseSpec?.content?.get("application/json")?.schema?.let { schema ->
                        val validator = ContractValidatorService(openApi)
                        validator.validateResponse(url, method, code, body).forEach { addIfNotDuplicate(issues, it) }
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
                if (requiresAuth) checkBrokenAuth(client, url, method, issues)

            } catch (e: Exception) {
                addNetworkIssue(issues, url, method, "Ошибка сети при GET/HEAD", e.message ?: "unknown")
            }
        }

        // -----------------------
        // POST / PUT / PATCH (Mass Assignment, Request Validation, Injection)
        // -----------------------
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
                    val resp = authService.performRequestWithAuth(httpMethod, url, authClientId, authClientSecret, {
                        contentType(ContentType.Application.Json)
                        setBody(body)
                        header("X-Scanner-Probe", "true")
                    }, issues)

                    val code = resp.status.value
                    val respBody = safeBodyText(resp)

                    // Mass Assignment heuristic
                    if ((method.equals("POST", true) || method.equals("PUT", true)) && code in 200..299) {
                        if (!respBody.contains("error", true) && !respBody.contains("validation", true) &&
                            (body.contains("isAdmin") || body.contains("role"))
                        ) {
                            addIfNotDuplicate(issues, Issue("MASS_ASSIGNMENT", url, method, "MEDIUM", "POST/PUT принял дополнительные/административные поля", "HTTP $code, body: ${respBody.take(500)}"))
                        }
                    }

                    // Request contract validation
                    operation.requestBody?.content?.get("application/json")?.schema?.let { schema ->
                        val validator = ContractValidatorService(openApi)
                        validator.validateResponse(url, method, code, body).forEach { addIfNotDuplicate(issues, it) }
                    }

                    // Insufficient logging
                    if (respBody.contains("Exception", true) || respBody.contains("StackTrace", true) || respBody.contains("java.lang", true)) {
                        addIfNotDuplicate(issues, Issue("INSUFFICIENT_LOGGING", url, method, "MEDIUM", "Сервер возвращает подробные ошибки/стек-трейс", respBody.take(1000)))
                    }

                    // Injection detection
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

        // -----------------------
        // Function-level / Admin / Debug / Config checks
        // -----------------------
        val adminCandidates = listOf("/admin", "/debug", "/config", "/test", "/internal")
        for (suf in adminCandidates) {
            try {
                val adminUrl = url.trimEnd('/') + suf
                val resp = authService.performRequestWithAuth(HttpMethod.Get, adminUrl, authClientId, authClientSecret, null, issues)
                if (resp.status.value in 200..299) {
                    addIfNotDuplicate(issues, Issue("BROKEN_FUNCTION_LEVEL_AUTH", adminUrl, "GET", "HIGH", "Административный/debug эндпоинт доступен публично", "HTTP ${resp.status.value}"))
                }
            } catch (_: Exception) {}
        }

        // Quick injection via query param
        try {
            val injUrl = if (url.contains("?")) "$url&__scan_inj=' OR '1'='1" else "$url?__scan_inj=' OR '1'='1"
            val resp = authService.performRequestWithAuth(HttpMethod.Get, injUrl, authClientId, authClientSecret, null, issues)
            if (resp.status.value in 200..299) {
                val b = safeBodyText(resp)
                if (b.contains("sql", true) || b.contains("syntax", true) || b.contains("exception", true)) {
                    addIfNotDuplicate(issues, Issue("INJECTION", injUrl, "GET", "HIGH", "Потенциальная инъекция через query param", b.take(1000)))
                }
            }
        } catch (_: Exception) {}
    }
}
