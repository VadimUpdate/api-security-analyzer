package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.ScanReport
import com.example.apianalyzer.model.Summary
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.plugin.BuiltinCheckersPlugin
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.client.plugins.*
import io.ktor.client.network.sockets.*
import io.ktor.http.*
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.parser.OpenAPIV3Parser
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.net.ConnectException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.time.Instant
import kotlin.collections.groupingBy
import kotlin.collections.eachCount

@Service
class ApiScanService(
    private val clientProvider: ClientProvider = ClientProvider(),
    private val authService: AuthService = AuthService(clientProvider)
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val mapper = jacksonObjectMapper()
    private val client get() = clientProvider.client

    fun runScan(
        specUrl: String,
        targetUrl: String,
        maxConcurrency: Int = 6,
        politenessDelayMs: Int = 150,
        authClientId: String = "",
        authClientSecret: String = "",
        enableFuzzing: Boolean = false
    ): ScanReport = runBlocking {
        val issues = mutableListOf<Issue>()

        val specText = try {
            client.get(specUrl).bodyAsText()
        } catch (e: Exception) {
            issues.add(Issue(
                type = "SPEC_LOAD_ERROR",
                severity = Severity.HIGH,
                description = "Не удалось загрузить спецификацию: ${e.message ?: "unknown"}"
            ))
            return@runBlocking emptyScanReport(specUrl, targetUrl, issues)
        }

        val openApi: OpenAPI = try {
            OpenAPIV3Parser().readContents(specText, null, null).openAPI
                ?: throw IllegalStateException("parser returned null openAPI")
        } catch (e: Exception) {
            issues.add(Issue(
                type = "SPEC_PARSE_ERROR",
                severity = Severity.HIGH,
                description = "Ошибка парсинга спецификации: ${e.message ?: "unknown"}"
            ))
            return@runBlocking emptyScanReport(specUrl, targetUrl, issues)
        }

        val pathsMap = openApi.paths ?: emptyMap()
        val totalEndpoints = pathsMap.entries.sumOf { (_, pathItem) -> extractOperations(pathItem).size }

        if (authClientId.isNotBlank() && authClientSecret.isNotBlank()) {
            authService.authToken = authService.obtainBearerTokenFromSpecOrFallback(
                openApi, targetUrl, authClientId, authClientSecret, issues
            )
            if (authService.authToken.isNullOrBlank()) issues.add(Issue(
                type = "AUTH_TOKEN_FAIL",
                severity = Severity.HIGH,
                description = "Не удалось получить токен автоматически"
            ))
        }

        val reachable = checkTargetReachable(client, targetUrl, pathsMap.keys, issues)
        if (!reachable) return@runBlocking ScanReport(
            specUrl = specUrl,
            targetUrl = targetUrl,
            timestamp = Instant.now(),
            totalEndpoints = totalEndpoints,
            summary = Summary(issues.size, issues.groupingBy { it.type }.eachCount(), pathsMap.size),
            issues = issues
        )

        val pluginRegistry = PluginRegistry().apply {
            register(BuiltinCheckersPlugin(
                clientProvider,
                authService,
                enableFuzz = enableFuzzing,
                politenessDelayMs = politenessDelayMs.toLong(),
                maxFuzzConcurrency = maxConcurrency,
                maxFuzzPayloads = 10
            ))
        }

        val semaphore = Semaphore(maxConcurrency)
        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()
            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)
                for ((method, operation) in operations) {
                    if (operation == null) continue
                    val combinedParams = (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())
                    val testUrl = buildUrlFromPath(targetUrl, pathTemplate, combinedParams)

                    jobs += async {
                        semaphore.withPermit {
                            delay(politenessDelayMs.toLong())
                            try {
                                pluginRegistry.runAll(testUrl, method, operation, issues, enableFuzzing)
                                performEnhancedChecks(testUrl, method, issues)
                            } catch (e: Exception) {
                                log.debug("Check failed for {} {}: {}", method, testUrl, e.message)
                                classifyNetworkError(e, testUrl, method, issues)
                            }
                        }
                    }
                }
            }
            jobs.awaitAll()
        }

        runGlobalChecks(client, targetUrl, issues)

        ScanReport(
            specUrl = specUrl,
            targetUrl = targetUrl,
            timestamp = Instant.now(),
            totalEndpoints = totalEndpoints,
            summary = Summary(
                totalIssues = issues.size,
                issuesByType = issues.groupingBy { it.type }.eachCount(),
                uniqueEndpoints = pathsMap.size
            ),
            issues = issues
        )
    }

    private fun emptyScanReport(specUrl: String, targetUrl: String, issues: MutableList<Issue>) = ScanReport(
        specUrl = specUrl,
        targetUrl = targetUrl,
        timestamp = Instant.now(),
        totalEndpoints = 0,
        summary = Summary(0, emptyMap(), 0),
        issues = issues
    )

    // --- Вспомогательные функции (performEnhancedChecks, classifyNetworkError, checkSensitiveFields)
    private suspend fun performEnhancedChecks(url: String, method: String, issues: MutableList<Issue>) {
        val response: HttpResponse = try {
            client.request(url) {
                this.method = HttpMethod.parse(method)
                authService.authToken?.let { header("Authorization", "Bearer $it") }
            }
        } catch (e: Exception) {
            classifyNetworkError(e, url, method, issues)
            return
        }

        val statusCode = response.status.value
        when {
            statusCode == 401 -> issues.add(Issue("ENDPOINT_ERROR_STATUS", Severity.LOW,
                "Эндпоинт $url вернул HTTP 401 (требуется авторизация)", path=url, method=method, evidence="HTTP 401"))
            statusCode == 403 -> issues.add(Issue("ENDPOINT_ERROR_STATUS", Severity.LOW,
                "Эндпоинт $url вернул HTTP 403 — доступ запрещён", path=url, method=method, evidence="HTTP 403"))
            statusCode >= 500 -> issues.add(Issue("SERVER_ERROR", Severity.MEDIUM,
                "Эндпоинт $url вернул HTTP $statusCode — возможная ошибка сервера", path=url, method=method, evidence="HTTP $statusCode"))
        }

        val bodyText = response.bodyAsText()
        checkSensitiveFields(bodyText, url, method, issues)
    }

    private fun classifyNetworkError(e: Exception, url: String, method: String, issues: MutableList<Issue>) {
        when (e) {
            is SocketTimeoutException -> issues.add(Issue("NETWORK_TIMEOUT", Severity.MEDIUM,
                "Timeout при подключении к $url", path=url, method=method))
            is ConnectException, is SocketException -> issues.add(Issue("NETWORK_UNREACHABLE", Severity.MEDIUM,
                "Не удалось подключиться к $url: ${e.message}", path=url, method=method))
            else -> issues.add(Issue("NETWORK_ERROR", Severity.MEDIUM,
                "Ошибка сети при проверке $url: ${e.message}", path=url, method=method))
        }
    }

    private fun checkSensitiveFields(body: String?, url: String, method: String, issues: MutableList<Issue>) {
        if (body.isNullOrBlank()) return
        val sensitiveKeys = listOf("password", "token", "secret", "ssn", "creditCard", "dob")
        val json = try { mapper.readTree(body) } catch (e: Exception) { return }

        fun traverse(node: JsonNode) {
            when {
                node.isObject -> node.fields().forEach { (key, value) ->
                    if (sensitiveKeys.any { key.contains(it, ignoreCase = true) }) {
                        issues.add(Issue(
                            type = "EXCESSIVE_DATA_EXPOSURE",
                            severity = Severity.HIGH,
                            description = "Ответ $method $url содержит чувствительное поле: $key",
                            path = url,
                            method = method,
                            evidence = key
                        ))
                    }
                    traverse(value)
                }
                node.isArray -> node.forEach { traverse(it) }
            }
        }
        traverse(json)
    }
}
