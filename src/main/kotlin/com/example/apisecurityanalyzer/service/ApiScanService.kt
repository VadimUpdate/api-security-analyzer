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
        authClientSecret: String = "",
        enableFuzzing: Boolean = false       // ✅ новый флаг
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
                                // теперь передаем флаг фуззинга плагинам
                                pluginRegistry.runAll(testUrl, method, operation, issues, enableFuzzing)

                                // стандартные проверки
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

    // === дополнительные проверки ===
    private suspend fun performEnhancedChecks(url: String, method: String, issues: MutableList<Issue>) { /* ... */ }
    private fun classifyNetworkError(e: Exception, url: String, method: String, issues: MutableList<Issue>) { /* ... */ }
    private fun checkSensitiveFields(body: String?, url: String, method: String, issues: MutableList<Issue>) { /* ... */ }
}
