package com.example.apianalyzer.service

import java.net.SocketTimeoutException
import java.net.SocketException
import java.net.ConnectException
import com.example.apianalyzer.model.ScanReport
import com.example.apianalyzer.model.Summary
import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.plugin.BuiltinCheckersPlugin
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.client.plugins.*
import io.ktor.client.network.sockets.*
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.parser.OpenAPIV3Parser
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
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
    private val pluginRegistry = PluginRegistry().apply {
        register(BuiltinCheckersPlugin(clientProvider, authService))
    }

    fun runScan(
        specUrl: String,
        targetUrl: String,
        maxConcurrency: Int = 6,
        politenessDelayMs: Int = 150,
        authClientId: String = "",
        authClientSecret: String = ""
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
            return@runBlocking ScanReport(
                specUrl = specUrl,
                targetUrl = targetUrl,
                timestamp = Instant.now(),
                totalEndpoints = 0,
                summary = Summary(0, emptyMap(), 0),
                issues = issues
            )
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
            return@runBlocking ScanReport(
                specUrl = specUrl,
                targetUrl = targetUrl,
                timestamp = Instant.now(),
                totalEndpoints = 0,
                summary = Summary(0, emptyMap(), 0),
                issues = issues
            )
        }

        val pathsMap = openApi.paths ?: emptyMap()
        val totalEndpoints = pathsMap.entries.sumOf { (_, pathItem) -> extractOperations(pathItem).size }

        if (authClientId.isNotBlank() && authClientSecret.isNotBlank()) {
            authService.authToken = authService.obtainBearerTokenFromSpecOrFallback(openApi, targetUrl, authClientId, authClientSecret, issues)
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

        val semaphore = Semaphore(maxConcurrency)
        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()
            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)
                for ((method, operation) in operations) {
                    if (operation == null) continue
                    val combinedParams = (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())
                    val testUrl = buildUrlFromPath(targetUrl, pathTemplate, combinedParams)

                    val job: Deferred<Unit> = async {
                        semaphore.withPermit {
                            delay(politenessDelayMs.toLong())
                            try {
                                // основной плагинный анализ
                                pluginRegistry.runAll(testUrl, method, operation, issues)

                                // дополнительно проверяем HTTP-статусы и чувствительные данные
                                performEnhancedChecks(testUrl, method, issues)
                            } catch (e: Exception) {
                                log.debug("Check failed for {} {}: {}", method, testUrl, e.message)
                                classifyNetworkError(e, testUrl, method, issues)
                            }
                        }
                    }
                    jobs.add(job)
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

    // === Новые вспомогательные функции ===

    private suspend fun performEnhancedChecks(url: String, method: String, issues: MutableList<Issue>) {
        val response: HttpResponse = try {
            client.request(url) {
                when (method.uppercase()) {
                    "GET" -> this.method = io.ktor.http.HttpMethod.Get
                    "POST" -> this.method = io.ktor.http.HttpMethod.Post
                    "PUT" -> this.method = io.ktor.http.HttpMethod.Put
                    "PATCH" -> this.method = io.ktor.http.HttpMethod.Patch
                    "DELETE" -> this.method = io.ktor.http.HttpMethod.Delete
                    else -> this.method = io.ktor.http.HttpMethod.Get
                }
                authService.authToken?.let { header("Authorization", "Bearer $it") }
            }
        } catch (e: Exception) {
            classifyNetworkError(e, url, method, issues)
            return
        }

        val statusCode = response.status.value
        when {
            statusCode == 401 -> issues.add(Issue(
                type = "ENDPOINT_ERROR_STATUS",
                severity = Severity.LOW,
                description = "Эндпоинт $url вернул HTTP 401 (требуется авторизация)",
                path = url,
                method = method,
                evidence = "HTTP 401"
            ))
            statusCode == 403 -> issues.add(Issue(
                type = "ENDPOINT_ERROR_STATUS",
                severity = Severity.LOW,
                description = "Эндпоинт $url вернул HTTP 403 — доступ запрещён, это безопасно",
                path = url,
                method = method,
                evidence = "HTTP 403"
            ))
            statusCode >= 500 -> issues.add(Issue(
                type = "SERVER_ERROR",
                severity = Severity.MEDIUM,
                description = "Эндпоинт $url вернул HTTP $statusCode — возможная ошибка сервера",
                path = url,
                method = method,
                evidence = "HTTP $statusCode"
            ))
        }

        val bodyText = response.bodyAsText()
        checkSensitiveFields(bodyText, url, method, issues)
    }


    private fun classifyNetworkError(e: Exception, url: String, method: String, issues: MutableList<Issue>) {
        when (e) {
            is SocketTimeoutException -> issues.add(Issue(
                type = "NETWORK_TIMEOUT",
                severity = Severity.MEDIUM,
                description = "Timeout при подключении к $url",
                path = url,
                method = method
            ))
            is ConnectException, is SocketException -> issues.add(Issue(
                type = "NETWORK_UNREACHABLE",
                severity = Severity.MEDIUM,
                description = "Не удалось подключиться к $url: ${e.message}",
                path = url,
                method = method
            ))
            else -> issues.add(Issue(
                type = "NETWORK_ERROR",
                severity = Severity.MEDIUM,
                description = "Ошибка сети при проверке $url: ${e.message}",
                path = url,
                method = method
            ))
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
