package com.example.apianalyzer.service

import com.example.apianalyzer.model.*
import com.example.apianalyzer.plugin.BuiltinCheckersPlugin
import com.example.apianalyzer.plugin.PluginRegistry
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.call.*
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

@Service
class ApiScanService(
    private val clientProvider: ClientProvider = ClientProvider(),
    private val authService: AuthService = AuthService(clientProvider)
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val mapper = jacksonObjectMapper()
    private val client get() = clientProvider.client

    fun runScan(userInput: UserInput): ScanReport = runBlocking {
        val issues = mutableListOf<Issue>()

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

        // Получаем bankToken один раз
        val bankToken = try {
            authService.getBankToken(userInput.targetUrl, userInput.clientId, userInput.clientSecret, issues)
        } catch (e: Exception) {
            issues.add(Issue("AUTH_TOKEN_FAIL", Severity.HIGH, "Не удалось получить bank token: ${e.message}"))
            null
        }

        // Получаем consentId только если bankToken валиден
        val consentId = if (!bankToken.isNullOrBlank()) {
            try {
                authService.createConsent(
                    bankBaseUrl = userInput.targetUrl,
                    clientId = userInput.clientId,
                    clientSecret = userInput.clientSecret,
                    issues = issues
                )
            } catch (_: Exception) { null }
        } else null


        if (consentId.isNullOrBlank()) {
            issues.add(Issue("CONSENT_FAIL", Severity.HIGH, "Consent не получен или не одобрен"))
        }

        log.info("Bank token: $bankToken, Consent ID: $consentId")

        val plugin = BuiltinCheckersPlugin(
            clientProvider = clientProvider,
            authService = authService,
            bankBaseUrl = userInput.targetUrl,
            clientId = userInput.clientId,
            clientSecret = userInput.clientSecret,
            enableFuzzing = userInput.enableFuzzing
        )

        // Устанавливаем token и consent в фаззер заранее
        plugin.fuzzer.bankToken = bankToken ?: ""
        plugin.fuzzer.consentId = consentId ?: ""

        val pluginRegistry = PluginRegistry().apply { register(plugin) }

        // Получаем список accountId из /accounts
        val accountIds = if (!bankToken.isNullOrBlank() && !consentId.isNullOrBlank()) {
            getAccounts(userInput.targetUrl, bankToken, consentId, userInput.clientId)
        } else emptyList()
        log.info("Retrieved accountIds: $accountIds")

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
                                pluginRegistry.runAll(
                                    url = testUrl,
                                    method = method,
                                    operation = operation,
                                    issues = issues
                                )

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
            issues = issues,
            accountIds = accountIds
        )
    }

    private fun emptyReport(userInput: UserInput, issues: List<Issue>) =
        ScanReport(
            specUrl = userInput.specUrl,
            targetUrl = userInput.targetUrl,
            timestamp = Instant.now(),
            totalEndpoints = 0,
            summary = Summary(0, emptyMap(), 0),
            issues = issues,
            accountIds = emptyList()
        )

    private suspend fun performEnhancedChecks(
        url: String,
        method: String,
        issues: MutableList<Issue>,
        bankToken: String,
        consentId: String,
        userInput: UserInput
    ) {
        log.info("Performing enhanced check: $method $url")

        val response = try {
            client.request(url) {
                this.method = HttpMethod.parse(method)
                if (!url.contains("/auth/bank-token")) {
                    header("Authorization", "Bearer $bankToken")
                    header("X-Consent-Id", consentId)
                    header("X-Requesting-Bank", userInput.requestingBank)
                }
                if (this.method != HttpMethod.Get) {
                    contentType(ContentType.Application.Json)
                    setBody("{}")
                }
            }
        } catch (e: Exception) {
            classifyNetworkError(e, url, method, issues)
            return
        }

        val status = response.status.value
        val body = response.bodyAsText()

        if (status == 403) {
            issues.add(Issue("ENDPOINT_FORBIDDEN", Severity.LOW, "$method $url → 403", url, method))
        }

        checkSensitiveFields(body, url, method, issues)
    }

    private fun classifyNetworkError(e: Exception, url: String, method: String, issues: MutableList<Issue>) {
        when (e) {
            is SocketTimeoutException -> issues.add(Issue("NETWORK_TIMEOUT", Severity.MEDIUM, "Timeout: $url", url, method))
            is ConnectException, is SocketException -> issues.add(Issue("NETWORK_UNREACHABLE", Severity.MEDIUM, "Нет соединения: $url", url, method))
            else -> issues.add(Issue("NETWORK_ERROR", Severity.MEDIUM, "Ошибка сети: ${e.message}", url, method))
        }
        log.error("Network error on $method $url", e)
    }

    private fun checkSensitiveFields(body: String?, url: String, method: String, issues: MutableList<Issue>) {
        if (body.isNullOrBlank()) return
        val json = try { mapper.readTree(body) } catch (_: Exception) { return }

        val sensitive = listOf("password", "token", "secret", "ssn", "creditCard", "dob")

        fun traverse(node: JsonNode) {
            if (node.isObject) {
                node.fields().forEach { (key, value) ->
                    if (sensitive.any { key.contains(it, ignoreCase = true) }) {
                        issues.add(Issue("EXCESSIVE_DATA_EXPOSURE", Severity.HIGH, "Ответ содержит чувствительное поле: $key", url, method))
                    }
                    traverse(value)
                }
            }
            if (node.isArray) node.forEach { traverse(it) }
        }

        traverse(json)
    }

    private suspend fun getAccounts(bankBaseUrl: String, bankToken: String, consentId: String, requestingBank: String): List<String> {
        val url = "$bankBaseUrl/accounts?client_id=$requestingBank"
        return try {
            val response = client.request(url) {
                method = HttpMethod.Get
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", requestingBank)
                header("Accept", "application/json")
            }

            if (response.status.value != 200) {
                log.warn("Failed to fetch accounts: HTTP ${response.status.value}")
                return emptyList()
            }

            val body = response.bodyAsText()
            val json = mapper.readTree(body)
            val accountsNode = json.get("accounts") ?: return emptyList()
            accountsNode.mapNotNull { it.get("accountId")?.asText() }
        } catch (e: Exception) {
            classifyNetworkError(e, url, "GET", mutableListOf())
            emptyList()
        }
    }
}
