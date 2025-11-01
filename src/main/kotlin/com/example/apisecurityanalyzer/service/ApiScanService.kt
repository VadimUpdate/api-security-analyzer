package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.ScanReport
import com.example.apianalyzer.plugin.BuiltinCheckersPlugin
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.*
import io.ktor.client.call.*
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
        // сюда можно добавлять новые плагины
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

        val specText = try { client.get(specUrl).bodyAsText() }
        catch (e: Exception) {
            addIfNotDuplicate(issues, Issue("SPEC_LOAD_ERROR", specUrl, "GET", "HIGH", "Не удалось загрузить спецификацию", e.message ?: "unknown"))
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        val openApi = try {
            OpenAPIV3Parser().readContents(specText, null, null).openAPI
                ?: throw IllegalStateException("parser returned null openAPI")
        } catch (e: Exception) {
            addIfNotDuplicate(issues, Issue("SPEC_PARSE_ERROR", specUrl, "PARSE", "HIGH", "Ошибка парсинга спецификации", e.message ?: "unknown"))
            return@runBlocking ScanReport(specUrl, targetUrl, 0, issues, Instant.now().toString())
        }

        val pathsMap = openApi.paths ?: emptyMap()
        val totalEndpoints = pathsMap.entries.map { extractOperations(it.value).size }.sum()

        if (authClientId.isNotBlank() && authClientSecret.isNotBlank()) {
            authService.authToken = authService.obtainBearerTokenFromSpecOrFallback(openApi, targetUrl, authClientId, authClientSecret, issues)
            if (authService.authToken.isNullOrBlank()) addNetworkIssue(issues, targetUrl, "POST", "Не удалось получить токен автоматически", "token=null")
        }

        val reachable = checkTargetReachable(client, targetUrl, pathsMap.keys, issues)
        if (!reachable) return@runBlocking ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())

        val semaphore = Semaphore(maxConcurrency)
        coroutineScope {
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
                                pluginRegistry.runAll(testUrl, method, operation, issues)
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
        }

        runGlobalChecks(client, targetUrl, issues)

        ScanReport(specUrl, targetUrl, totalEndpoints, issues, Instant.now().toString())
    }
}
