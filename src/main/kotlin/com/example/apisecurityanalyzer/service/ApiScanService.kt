package com.example.apianalyzer.service

import com.example.apianalyzer.model.*
import com.example.apianalyzer.plugin.*
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.client.plugins.*
import io.ktor.http.*
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.parameters.Parameter
import io.swagger.v3.parser.OpenAPIV3Parser
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.springframework.stereotype.Service
import java.io.BufferedReader
import java.io.InputStreamReader
import java.time.Instant

@Service
class ApiScanService(
    private val clientProvider: ClientProvider = ClientProvider(),
    private val authService: AuthService = AuthService(clientProvider),
    private val cardService: CardService = CardService(clientProvider.client),
    private val consentService: ConsentService = ConsentService(clientProvider, authService)
) {
    private val mapper = jacksonObjectMapper()
    private val client get() = clientProvider.client

    fun runScan(userInput: UserInput): ScanReport = runBlocking {
        val issues = mutableListOf<Issue>()

        val specText = try {
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

        val bankToken = try {
            authService.getBankToken(userInput.targetUrl, userInput.clientId, userInput.clientSecret, issues)
        } catch (e: Exception) {
            issues.add(Issue("AUTH_TOKEN_FAIL", Severity.HIGH, "Не удалось получить bank token: ${e.message}"))
            null
        }

        val accountConsentId = if (!bankToken.isNullOrBlank()) consentService.createAccountConsent(userInput, bankToken, issues) else null
        val paymentConsentId = if (!bankToken.isNullOrBlank()) consentService.createPaymentConsent(userInput, bankToken, issues) else null
        var productRequestId: String? = null
        val productConsentId = if (!bankToken.isNullOrBlank()) {
            val pair = consentService.createProductAgreementConsent(userInput, bankToken, issues)
            productRequestId = pair.second
            pair.first
        } else null

        val builtinPlugin = BuiltinCheckersPlugin(clientProvider, consentService, userInput, bankToken ?: "")
        val pluginRegistry = PluginRegistry().apply { register(builtinPlugin) }

        // получить accountId/accountNumber/cardId
        val accountId: String? =
            if (!bankToken.isNullOrBlank() && !accountConsentId.isNullOrBlank())
                cardService.getFirstAccount(userInput.targetUrl, bankToken, accountConsentId, userInput.clientId)
            else null

        val accountNumber: String? =
            if (!bankToken.isNullOrBlank() && !accountConsentId.isNullOrBlank() && accountId != null)
                cardService.getFirstAccountNumber(userInput.targetUrl, bankToken, accountConsentId, userInput.clientId, accountId)
            else null

        val cardId: String? =
            if (!bankToken.isNullOrBlank() && !accountConsentId.isNullOrBlank() && accountNumber != null)
                cardService.getFirstCard(userInput.targetUrl, bankToken, accountConsentId, userInput.clientId, accountNumber)
            else null

        val semaphore = Semaphore(userInput.maxConcurrency)

        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()

            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)
                for ((method, operation) in operations) {
                    if (operation == null) continue
                    val combinedParams: List<Parameter> = (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())

                    val url = buildUrlForScan(
                        pathTemplate, combinedParams, userInput,
                        accountId, accountNumber, cardId,
                        paymentConsentId, productConsentId, productRequestId
                    )

                    jobs.add(async<Unit> {
                        semaphore.withPermit {
                            delay(userInput.politenessDelayMs.toLong())
                            try {
                                val requestBody = generateValidRequestBody(operation, userInput, accountNumber)

                                // делаем "контрактный" запрос с выбором ГОСТ/обычный
                                performRequestWithAuthAndBody(url, method, requestBody, bankToken, accountConsentId, issues, userInput.useGostGateway)

                                // выборочные проверки по флагам
                                builtinPlugin.runChecksByFlagsIfEnabled(
                                    url,
                                    method,
                                    operation,
                                    issues,
                                    userInput
                                )
                            } catch (ex: Exception) {
                                issues.add(Issue("SCAN_ERROR", Severity.MEDIUM, "Ошибка при запросе $url: ${ex.message}"))
                            }
                        }
                    })
                }
            }
            jobs.awaitAll()
        }

        // глобальные проверки по флагам
        if (userInput.enableRateLimiting || userInput.enableSensitiveFiles || userInput.enablePublicSwagger) {
            runGlobalChecks(client, userInput.targetUrl, issues, userInput)
        }

        return@runBlocking ScanReport(
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
            accountIds = listOfNotNull(accountId)
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

    private fun generateValidRequestBody(
        operation: io.swagger.v3.oas.models.Operation,
        userInput: UserInput,
        accountNumber: String?
    ): JsonNode? {
        val schema = operation.requestBody?.content?.values?.firstOrNull()?.schema ?: return null
        return buildSampleJsonFromSchema(schema, userInput, accountNumber)
    }

    private suspend fun performRequestWithAuthAndBody(
        url: String,
        method: String,
        body: JsonNode?,
        token: String?,
        consentId: String?,
        issues: MutableList<Issue>,
        useGostGateway: Boolean
    ) {
        try {
            if (useGostGateway) {
                val accessToken = token ?: throw IllegalStateException("Token required for GOST gateway")
                val result = executeGostCurl(url, method, accessToken, body)
                // можно логировать result, при необходимости парсить
            } else {
                client.request(url) {
                    this.method = HttpMethod.parse(method)
                    if (body != null) {
                        contentType(ContentType.Application.Json)
                        setBody(body.toString())
                    }
                    if (!token.isNullOrBlank()) header("Authorization", "Bearer $token")
                    if (!consentId.isNullOrBlank()) header("X-Consent-Id", consentId)
                }
            }
        } catch (ex: ClientRequestException) {
            issues.add(Issue("SPEC_MISMATCH", Severity.MEDIUM, "Ответ не соответствует спецификации: ${ex.response.status.value}"))
        } catch (ex: Exception) {
            issues.add(Issue("REQUEST_FAIL", Severity.MEDIUM, "Ошибка запроса: ${ex.message}"))
        }
    }

    private fun buildUrlForScan(
        pathTemplate: String,
        params: List<Parameter>,
        userInput: UserInput,
        accountId: String?,
        accountNumber: String?,
        cardId: String?,
        paymentConsentId: String?,
        productConsentId: String?,
        productRequestId: String?
    ): String {
        var url = pathTemplate

        if (url.contains("{account_id}") && accountId != null)
            url = url.replace("{account_id}", accountId)

        if (url.contains("{consent_id}")) {
            url = when {
                url.startsWith("/payment-consents") && paymentConsentId != null ->
                    url.replace("{consent_id}", paymentConsentId)

                url.startsWith("/product-agreement-consents") && productConsentId != null ->
                    url.replace("{consent_id}", productConsentId)

                else -> url
            }
        }

        if (url.contains("{id}") && productRequestId != null)
            url = url.replace("{id}", productRequestId)

        if (url.startsWith("/product-agreements"))
            url += "?client_id=${userInput.clientId}-1"

        return buildUrlFromPath(userInput.targetUrl, url, params).removeQueryParam("client_id")
    }

    private fun buildSampleJsonFromSchema(
        schema: io.swagger.v3.oas.models.media.Schema<*>,
        userInput: UserInput,
        accountNumber: String?
    ): JsonNode {
        val node: ObjectNode = mapper.createObjectNode()

        schema.properties?.forEach { (key, prop) ->
            when {
                prop.type == "string" -> {
                    node.put(
                        key,
                        when (key.lowercase()) {
                            "client_id" -> userInput.clientId
                            "bank" -> userInput.requestingBank
                            "account_number" -> accountNumber ?: "00000000"
                            else -> "sample"
                        }
                    )
                }
                prop.type == "integer" -> node.put(key, 1)
                prop.type == "number" -> node.put(key, 1.0)
                prop.type == "boolean" -> node.put(key, true)
                prop.type == "object" ->
                    node.set<JsonNode>(key, buildSampleJsonFromSchema(prop, userInput, accountNumber))

                else -> node.put(key, "sample")
            }
        }
        return node
    }

    /**
     * Выполнение запроса через curl с поддержкой ГОСТ
     */
    private fun executeGostCurl(url: String, method: String, token: String, body: JsonNode?): String {
        val command = mutableListOf(
            "curl", "-v", "-k",
            "-X", method,
            "-H", "Authorization: Bearer $token",
            "-H", "Content-Type: application/json",
            url
        )
        if (body != null) {
            command.addAll(listOf("-d", body.toString()))
        }

        val process = ProcessBuilder(command).start()
        val result = StringBuilder()

        BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                result.append(line).append("\n")
            }
        }
        process.waitFor()
        return result.toString()
    }
}

/**
 * Глобальные проверки с учётом флагов включения
 */
suspend fun runGlobalChecks(
    client: io.ktor.client.HttpClient,
    baseUrl: String,
    issues: MutableList<Issue>,
    userInput: UserInput
) {
    if (userInput.enableRateLimiting)
        checkRateLimiting(client, baseUrl, issues)

    if (userInput.enableSensitiveFiles)
        checkSensitiveFiles(client, baseUrl, issues)

    if (userInput.enablePublicSwagger)
        checkPublicSwagger(client, baseUrl, issues)
}

// Заглушки для методов, чтобы проект компилировался
suspend fun checkRateLimiting(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
suspend fun checkSensitiveFiles(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
suspend fun checkPublicSwagger(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
