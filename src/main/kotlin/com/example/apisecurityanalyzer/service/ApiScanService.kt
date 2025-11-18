package com.example.apianalyzer.service

import com.example.apianalyzer.model.*
import com.example.apianalyzer.plugin.BuiltinCheckersPlugin
import com.example.apianalyzer.plugin.PluginRegistry
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.parser.OpenAPIV3Parser
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.springframework.stereotype.Service
import java.time.Instant

@Service
class ApiScanService(
    private val clientProvider: ClientProvider = ClientProvider(),
    private val authService: AuthService = AuthService(clientProvider)
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

        // Основной bank token
        val bankToken = try {
            authService.getBankToken(userInput.targetUrl, userInput.clientId, userInput.clientSecret, issues)
        } catch (e: Exception) {
            issues.add(Issue("AUTH_TOKEN_FAIL", Severity.HIGH, "Не удалось получить bank token: ${e.message}"))
            null
        }

        // Consent для аккаунтов (read access)
        val accountConsentId = if (!bankToken.isNullOrBlank()) {
            try {
                authService.createConsent(
                    bankBaseUrl = userInput.targetUrl,
                    clientId = userInput.clientId,
                    clientSecret = userInput.clientSecret,
                    issues = issues
                )
            } catch (_: Exception) { null }
        } else null

        if (accountConsentId.isNullOrBlank() && !bankToken.isNullOrBlank()) {
            issues.add(Issue("CONSENT_FAIL", Severity.HIGH, "Account consent не получен или не одобрен"))
        }

        // Consent для платежей (payment access)
        val paymentConsentId = if (!bankToken.isNullOrBlank()) {
            try {
                createPaymentConsent(userInput, bankToken, issues)
            } catch (_: Exception) { null }
        } else null

        if (paymentConsentId.isNullOrBlank() && !bankToken.isNullOrBlank()) {
            issues.add(Issue("PAYMENT_CONSENT_FAIL", Severity.HIGH, "Payment consent не получен или не одобрен"))
        }

        val plugin = BuiltinCheckersPlugin(
            clientProvider = clientProvider,
            authService = authService,
            bankBaseUrl = userInput.targetUrl,
            clientId = userInput.clientId,
            clientSecret = userInput.clientSecret,
            enableFuzzing = userInput.enableFuzzing
        )

        // Передаём разные consent в fuzzer
        plugin.fuzzer.bankToken = bankToken ?: ""
        plugin.fuzzer.consentId = paymentConsentId ?: accountConsentId ?: ""

        val pluginRegistry = PluginRegistry().apply { register(plugin) }

        val accountId: String? =
            if (!bankToken.isNullOrBlank() && !accountConsentId.isNullOrBlank())
                getFirstAccount(userInput.targetUrl, bankToken, accountConsentId, userInput.clientId)
            else null

        val semaphore = Semaphore(userInput.maxConcurrency)

        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()

            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)

                for ((method, operation) in operations) {
                    if (operation == null) continue

                    val combinedParams = (pathItem.parameters ?: emptyList()) +
                            (operation.parameters ?: emptyList())

                    val url = when {
                        pathTemplate.contains("{account_id}") && accountId != null ->
                            buildUrlFromPath(
                                userInput.targetUrl,
                                pathTemplate.replace("{account_id}", accountId),
                                combinedParams
                            ).removeQueryParam("client_id")

                        pathTemplate == "/accounts" && method == "POST" ->
                            buildUrlFromPath(userInput.targetUrl, pathTemplate, combinedParams)

                        pathTemplate.contains("{consent_id}") && pathTemplate.startsWith("/payment-consents") && paymentConsentId != null ->
                            buildUrlFromPath(
                                userInput.targetUrl,
                                pathTemplate.replace("{consent_id}", paymentConsentId),
                                combinedParams
                            )

                        else ->
                            buildUrlFromPath(
                                userInput.targetUrl,
                                pathTemplate,
                                combinedParams
                            ).removeQueryParam("client_id")
                    }

                    jobs += async {
                        semaphore.withPermit {
                            delay(userInput.politenessDelayMs.toLong())

                            try {
                                pluginRegistry.runAll(
                                    url = url,
                                    method = method,
                                    operation = operation,
                                    issues = issues
                                )

                                if (!bankToken.isNullOrBlank()) {
                                    val consentToUse = if (pathTemplate.startsWith("/payment-consents")) paymentConsentId else accountConsentId
                                    if (!consentToUse.isNullOrBlank()) {
                                        performEnhancedChecks(
                                            url = url,
                                            method = method,
                                            issues = issues,
                                            bankToken = bankToken,
                                            consentId = consentToUse,
                                            userInput = userInput
                                        )
                                    }
                                }
                            } catch (_: Exception) {}
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

    private suspend fun performEnhancedChecks(
        url: String,
        method: String,
        issues: MutableList<Issue>,
        bankToken: String,
        consentId: String,
        userInput: UserInput
    ) {
        val httpMethod = HttpMethod.parse(method)
        val finalUrl = url

        val response = try {
            client.request(finalUrl) {
                this.method = httpMethod
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", userInput.requestingBank)

                if (httpMethod != HttpMethod.Get) {
                    contentType(ContentType.Application.Json)
                    setBody("{}")
                }
            }
        } catch (ex: Exception) {
            issues.add(
                Issue("REQUEST_FAILED", Severity.MEDIUM, "$method $finalUrl → Exception: ${ex.message}")
            )
            return
        }

        val status = response.status.value
        val body = runCatching { response.bodyAsText() }.getOrNull()

        if (status == 403) {
            issues.add(
                Issue("ENDPOINT_FORBIDDEN", Severity.LOW, "$method $finalUrl → 403", finalUrl, method)
            )
        }

        checkSensitiveFields(body, finalUrl, method, issues)
    }

    private fun checkSensitiveFields(body: String?, url: String, method: String, issues: MutableList<Issue>) {
        if (body.isNullOrBlank()) return
        val json = runCatching { mapper.readTree(body) }.getOrNull() ?: return

        val sensitive = listOf("password", "token", "secret", "ssn", "creditCard", "dob")

        fun traverse(node: JsonNode) {
            if (node.isObject) {
                node.fields().forEach { (key, value) ->
                    if (sensitive.any { key.contains(it, ignoreCase = true) }) {
                        issues.add(
                            Issue("EXCESSIVE_DATA_EXPOSURE", Severity.HIGH,
                                "Ответ содержит чувствительное поле: $key", url, method)
                        )
                    }
                    traverse(value)
                }
            } else if (node.isArray) {
                node.forEach { traverse(it) }
            }
        }

        traverse(json)
    }

    private suspend fun getFirstAccount(
        bankBaseUrl: String,
        bankToken: String,
        consentId: String,
        requestingBank: String
    ): String? {
        val url = "$bankBaseUrl/accounts?client_id=${requestingBank}-1"

        return try {
            val response = client.request(url) {
                method = HttpMethod.Get
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", requestingBank)
                header("Accept", "application/json")
            }

            if (response.status.value != 200) return null

            val body = response.bodyAsText()
            val json = mapper.readTree(body)
            val accountsNode = json.path("data").path("account")

            if (!accountsNode.isArray || accountsNode.isEmpty) return null

            accountsNode.first().path("accountId").asText(null)
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun createPaymentConsent(
        userInput: UserInput,
        bankToken: String,
        issues: MutableList<Issue>
    ): String? {
        val url = "${userInput.targetUrl}/payment-consents/request"

        return try {
            val response = client.post(url) {
                contentType(ContentType.Application.Json)
                header("Authorization", "Bearer $bankToken")
                header("X-Requesting-Bank", userInput.requestingBank)
                setBody("""{
                      "requesting_bank": "${userInput.requestingBank}",
                      "client_id": "${userInput.clientId}-1",
                      "consent_type": "single_use",
                      "amount": 100.0,
                      "debtor_account": "",
                      "reference": "API scan payment"
                    }""".trimIndent())
            }

            if (response.status.value != 200) return null

            val body = response.bodyAsText()
            val json = mapper.readTree(body)
            json.path("consent_id").asText(null)
        } catch (ex: Exception) {
            issues.add(Issue("PAYMENT_CONSENT_FAIL", Severity.HIGH, "Не удалось создать Payment Consent: ${ex.message}"))
            null
        }
    }

    private fun String.removeQueryParam(param: String): String {
        val uri = java.net.URI(this)
        val query = uri.query?.split("&")
            ?.filterNot { it.startsWith("$param=") }
            ?.joinToString("&")

        return java.net.URI(uri.scheme, uri.authority, uri.path, query, uri.fragment).toString()
    }
}
