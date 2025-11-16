package com.example.apianalyzer.service

import com.example.apianalyzer.model.*
import com.example.apianalyzer.plugin.BuiltinCheckersPlugin
import com.example.apianalyzer.plugin.PluginRegistry
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
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

@Service
class ApiScanService(
    private val clientProvider: ClientProvider = ClientProvider(),
    private val authService: AuthService = AuthService(clientProvider)
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val mapper = jacksonObjectMapper()
    private val client: HttpClient get() = clientProvider.client

    fun runScan(userInput: UserInput): ScanReport = runBlocking {
        val issues = mutableListOf<Issue>()

        // Load OpenAPI spec
        val specText = try {
            log.info("Loading OpenAPI spec from ${userInput.specUrl}")
            client.get(userInput.specUrl).bodyAsText()
        } catch (e: Exception) {
            issues.add(Issue("SPEC_LOAD_ERROR", Severity.HIGH, "Ошибка загрузки спецификации: ${e.message}"))
            return@runBlocking emptyReport(userInput, issues)
        }

        val openApi: OpenAPI = try {
            OpenAPIV3Parser().readContents(specText, null, null).openAPI
                ?: throw IllegalStateException("Parser returned null")
        } catch (e: Exception) {
            issues.add(Issue("SPEC_PARSE_ERROR", Severity.HIGH, "Ошибка парсинга спецификации: ${e.message}"))
            return@runBlocking emptyReport(userInput, issues)
        }

        val pathsMap = openApi.paths ?: emptyMap()
        val totalEndpoints = pathsMap.entries.sumOf { (_, pi) -> extractOperations(pi).size }

        // Get bank token
        val bankToken = try {
            authService.fetchBankToken(
                bankBaseUrl = userInput.targetUrl.trimEnd('/'),
                clientId = userInput.clientId,
                clientSecret = userInput.clientSecret,
                issues = issues
            )
        } catch (e: Exception) {
            issues.add(Issue("AUTH_TOKEN_FAIL", Severity.HIGH, "Не удалось получить bank token: ${e.message}"))
            null
        }

        // Create consent
        val consentId = if (!bankToken.isNullOrBlank()) {
            try {
                authService.createConsent(userInput.clientId)
            } catch (e: Exception) {
                issues.add(Issue("CONSENT_REQUEST_FAIL", Severity.HIGH, "Ошибка при создании consent: ${e.message}"))
                null
            }
        } else null

        if (consentId.isNullOrBlank()) {
            issues.add(Issue("CONSENT_FAIL", Severity.HIGH, "Consent не получен или не одобрен"))
        }

        log.info("Bank token: $bankToken, Consent ID: $consentId")

        // Plugin system
        val pluginRegistry = PluginRegistry().apply {
            register(
                BuiltinCheckersPlugin(
                    clientProvider = clientProvider,
                    authService = authService,
                    bankBaseUrl = userInput.targetUrl.trimEnd('/'),
                    clientId = userInput.clientId,
                    clientSecret = userInput.clientSecret,
                    enableFuzzing = userInput.enableFuzzing,
                    politenessDelayMs = userInput.politenessDelayMs.toLong(),
                    maxConcurrency = userInput.maxConcurrency
                )
            )
        }

        // Parallel scanning
        val semaphore = Semaphore(userInput.maxConcurrency)
        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()
            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)
                for ((method, operation) in operations) {
                    if (operation == null) continue
                    val combinedParams = (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())
                    val testUrl = buildUrlFromPath(userInput.targetUrl, pathTemplate, combinedParams)
                    jobs += async {
                        semaphore.withPermit {
                            delay(userInput.politenessDelayMs.toLong())
                            try {
                                pluginRegistry.runAll(testUrl, method, operation, issues, userInput.enableFuzzing)

                                if (!bankToken.isNullOrBlank() && !consentId.isNullOrBlank()) {
                                    performEnhancedChecks(
                                        url = testUrl,
                                        method = method,
                                        issues = issues,
                                        bankToken = bankToken,
                                        consentId = consentId,
                                        userInput = userInput
                                    )
                                }
                            } catch (e: Exception) {
                                classifyNetworkError(e, testUrl, method, issues)
                            }
                        }
                    }
                }
            }
            jobs.awaitAll()
        }

        runGlobalChecks(client, userInput.targetUrl, issues)

        ScanReport(
            specUrl = userInput.specUrl,
            targetUrl = userInput.targetUrl,
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

    private fun emptyReport(userInput: UserInput, issues: List<Issue>) =
        ScanReport(
            specUrl = userInput.specUrl,
            targetUrl = userInput.targetUrl,
            timestamp = Instant.now(),
            totalEndpoints = 0,
            summary = Summary(0, emptyMap(), 0),
            issues = issues
        )

    private suspend fun performEnhancedChecks(
        url: String,
        method: String,
        issues: MutableList<Issue>,
        bankToken: String,
        consentId: String,
        userInput: UserInput
    ) {
        val response = try {
            authService.performRequestWithAuth(
                method = HttpMethod.parse(method),
                url = url,
                bankBaseUrl = userInput.targetUrl.trimEnd('/'),
                clientId = userInput.clientId,
                clientSecret = userInput.clientSecret,
                consentId = consentId,
                bankToken = bankToken,
                bodyBlock = {
                    header("Authorization", "Bearer $bankToken")
                    header("X-Consent-Id", consentId)
                    header("X-Requesting-Bank", userInput.clientId)
                },
                issues = issues
            )
        } catch (e: Exception) {
            classifyNetworkError(e, url, method, issues)
            return
        }

        val status = response.status.value
        val body = response.bodyAsText()

        if (status == 403) issues.add(Issue("ENDPOINT_FORBIDDEN", Severity.LOW, "$method $url → HTTP 403", url, method))
        checkSensitiveFields(body, url, method, issues)
    }

    private fun classifyNetworkError(e: Exception, url: String, method: String, issues: MutableList<Issue>) {
        when (e) {
            is SocketTimeoutException -> issues.add(Issue("NETWORK_TIMEOUT", Severity.MEDIUM, "Timeout: $url", url, method))
            is ConnectException, is SocketException -> issues.add(Issue("NETWORK_UNREACHABLE", Severity.MEDIUM, "Нет соединения: $url", url, method))
            else -> issues.add(Issue("NETWORK_ERROR", Severity.MEDIUM, "Ошибка сети: ${e.message}", url, method))
        }
    }

    private fun checkSensitiveFields(body: String?, url: String, method: String, issues: MutableList<Issue>) {
        if (body.isNullOrBlank()) return
        val json = try { mapper.readTree(body) } catch (_: Exception) { return }
        val sensitive = listOf("password","token","secret","ssn","creditCard","dob")
        fun traverse(node: com.fasterxml.jackson.databind.JsonNode) {
            if (node.isObject) node.fields().forEach { (key, value) ->
                if (sensitive.any { key.contains(it, ignoreCase = true) }) {
                    issues.add(Issue("EXCESSIVE_DATA_EXPOSURE", Severity.HIGH, "Ответ содержит чувствительное поле: $key", url, method))
                }
                traverse(value)
            }
            if (node.isArray) node.forEach { traverse(it) }
        }
        traverse(json)
    }
}
