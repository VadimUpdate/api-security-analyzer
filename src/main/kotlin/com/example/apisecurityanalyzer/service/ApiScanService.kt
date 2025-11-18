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
import io.ktor.http.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.jackson.*
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.parameters.Parameter
import io.swagger.v3.parser.OpenAPIV3Parser
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.springframework.stereotype.Service
import java.time.Instant
import io.ktor.client.request.setBody
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.get

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

        val bankToken = try {
            authService.getBankToken(userInput.targetUrl, userInput.clientId, userInput.clientSecret, issues)
        } catch (e: Exception) {
            issues.add(Issue("AUTH_TOKEN_FAIL", Severity.HIGH, "Не удалось получить bank token: ${e.message}"))
            null
        }

        val accountConsentId = if (!bankToken.isNullOrBlank()) {
            try { authService.createConsent(userInput.targetUrl, userInput.clientId, userInput.clientSecret, issues) } catch (_: Exception) { null }
        } else null

        if (accountConsentId.isNullOrBlank() && !bankToken.isNullOrBlank())
            issues.add(Issue("CONSENT_FAIL", Severity.HIGH, "Account consent не получен или не одобрен"))

        val paymentConsentId = if (!bankToken.isNullOrBlank()) {
            try { createPaymentConsent(userInput, bankToken, issues) } catch (_: Exception) { null }
        } else null

        if (paymentConsentId.isNullOrBlank() && !bankToken.isNullOrBlank())
            issues.add(Issue("PAYMENT_CONSENT_FAIL", Severity.HIGH, "Payment consent не получен или не одобрен"))

        var productRequestId: String? = null
        val productConsentId = if (!bankToken.isNullOrBlank()) {
            try {
                val (consentId, requestId) = createProductAgreementConsent(userInput, bankToken, issues)
                productRequestId = requestId
                consentId
            } catch (_: Exception) { null }
        } else null

        if (productConsentId.isNullOrBlank() && !bankToken.isNullOrBlank())
            issues.add(Issue("PRODUCT_CONSENT_FAIL", Severity.HIGH, "Product agreement consent не получен или не одобрен"))

        val plugin = BuiltinCheckersPlugin(
            clientProvider = clientProvider,
            authService = authService,
            bankBaseUrl = userInput.targetUrl,
            clientId = userInput.clientId,
            clientSecret = userInput.clientSecret,
            enableFuzzing = userInput.enableFuzzing
        )

        plugin.fuzzer.bankToken = bankToken ?: ""
        plugin.fuzzer.consentId = paymentConsentId ?: accountConsentId ?: productConsentId ?: ""

        val pluginRegistry = PluginRegistry().apply { register(plugin) }

        val accountId: String? =
            if (!bankToken.isNullOrBlank() && !accountConsentId.isNullOrBlank())
                getFirstAccount(userInput.targetUrl, bankToken, accountConsentId, userInput.clientId)
            else null

        val accountNumber: String? =
            if (!bankToken.isNullOrBlank() && !accountConsentId.isNullOrBlank() && accountId != null)
                getFirstAccountNumber(userInput.targetUrl, bankToken, accountConsentId, userInput.clientId, accountId)
            else null

        val cardId: String? =
            if (!bankToken.isNullOrBlank() && !accountConsentId.isNullOrBlank() && accountNumber != null)
                getFirstCard(userInput.targetUrl, bankToken, accountConsentId, userInput.clientId, accountNumber)
            else null

        val semaphore = Semaphore(userInput.maxConcurrency)

        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()

            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)
                for ((method, operation) in operations) {
                    if (operation == null) continue

                    val combinedParams: List<Parameter> =
                        (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())

                    val url = when {
                        pathTemplate.contains("{account_id}") && accountId != null ->
                            buildUrlFromPath(userInput.targetUrl, pathTemplate.replace("{account_id}", accountId), combinedParams)
                                .removeQueryParam("client_id")

                        pathTemplate.startsWith("/cards") ->
                            handleCardPaths(pathTemplate, userInput, combinedParams, accountNumber, cardId, accountConsentId, bankToken)

                        pathTemplate == "/accounts" && method == "POST" ->
                            buildUrlFromPath(userInput.targetUrl, pathTemplate, combinedParams)

                        pathTemplate.contains("{consent_id}") && pathTemplate.startsWith("/payment-consents") && paymentConsentId != null ->
                            buildUrlFromPath(userInput.targetUrl, pathTemplate.replace("{consent_id}", paymentConsentId), combinedParams)

                        pathTemplate.contains("{consent_id}") && pathTemplate.startsWith("/product-agreement-consents") && productConsentId != null ->
                            buildUrlFromPath(userInput.targetUrl, pathTemplate.replace("{consent_id}", productConsentId), combinedParams)

                        pathTemplate.contains("{id}") && pathTemplate.startsWith("/product-agreements") && productRequestId != null ->
                            buildUrlFromPath(userInput.targetUrl, pathTemplate.replace("{id}", productRequestId), combinedParams)

                        pathTemplate == "/product-agreements" -> {
                            val baseUrl = buildUrlFromPath(userInput.targetUrl, pathTemplate, combinedParams)
                            "$baseUrl?client_id=${userInput.clientId}-1"
                        }

                        else ->
                            buildUrlFromPath(userInput.targetUrl, pathTemplate, combinedParams)
                                .removeQueryParam("client_id")
                    }

                    jobs += async {
                        semaphore.withPermit {
                            delay(userInput.politenessDelayMs.toLong())
                            try {
                                pluginRegistry.runAll(url, method, operation, issues)

                                if (!bankToken.isNullOrBlank()) {
                                    val consentToUse = when {
                                        pathTemplate.startsWith("/payment-consents") -> paymentConsentId
                                        pathTemplate.startsWith("/product-agreement-consents") -> productConsentId
                                        pathTemplate.startsWith("/product-agreements") -> productConsentId
                                        pathTemplate.startsWith("/cards") -> accountConsentId
                                        else -> accountConsentId
                                    }
                                    if (!consentToUse.isNullOrBlank())
                                        performEnhancedChecks(url, method, issues, bankToken, consentToUse, userInput, productRequestId)
                                }
                            } catch (_: Exception) {}
                        }
                    }
                }
            }
            jobs.awaitAll()
        }

        runGlobalChecks(client, userInput.targetUrl, issues)

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

    // ----------------------------------------------------------------------
    // КАРТЫ
    private fun handleCardPaths(
        pathTemplate: String,
        userInput: UserInput,
        combinedParams: List<Parameter>,
        accountNumber: String? = null,
        cardId: String? = null,
        accountConsentId: String? = null,
        bankToken: String? = null
    ): String {
        val base = userInput.targetUrl

        return when {
            pathTemplate == "/cards" -> {
                if (accountNumber.isNullOrBlank() || accountConsentId.isNullOrBlank() || bankToken.isNullOrBlank()) {
                    return "$base/cards?client_id=${userInput.clientId}-1"
                }

                val existingCardId = runBlocking {
                    try {
                        val resp = client.get("$base/cards?client_id=${userInput.clientId}-1&account_id=$accountNumber") {
                            header("Authorization", "Bearer $bankToken")
                            header("X-Consent-Id", accountConsentId)
                            header("X-Requesting-Bank", userInput.clientId)
                            header("Accept", "application/json")
                        }
                        if (resp.status.value != 200) null
                        else mapper.readTree(resp.bodyAsText()).path("data").path("cards").firstOrNull()?.path("cardId")?.asText()
                    } catch (_: Exception) { null }
                }

                if (!existingCardId.isNullOrBlank()) {
                    return buildUrlFromPath(base, pathTemplate, combinedParams)
                }

                runBlocking {
                    issueNewCard(
                        bankBaseUrl = base,
                        bankToken = bankToken,
                        consentId = accountConsentId,
                        requestingBank = userInput.clientId,
                        clientId = userInput.clientId,
                        accountNumber = accountNumber
                    )
                }

                buildUrlFromPath(base, pathTemplate, combinedParams)
            }

            pathTemplate.contains("{card_id}") -> {
                val realCardId = cardId ?: "card-sample-id"
                buildUrlFromPath(base, pathTemplate.replace("{card_id}", realCardId), combinedParams)
            }

            else -> buildUrlFromPath(base, pathTemplate, combinedParams)
        }
    }

    private suspend fun getFirstAccountNumber(
        bankBaseUrl: String,
        bankToken: String,
        consentId: String,
        clientId: String,
        accountId: String
    ): String? {
        val url = "$bankBaseUrl/accounts?client_id=${clientId}-1"
        return try {
            val response = client.request(url) {
                method = HttpMethod.Get
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", clientId)
                header("Accept", "application/json")
            }
            val accountsNode = mapper.readTree(response.bodyAsText()).path("data").path("account")
            accountsNode.firstOrNull()?.path("accountNumber")?.asText()
        } catch (_: Exception) { null }
    }

    private suspend fun getFirstCard(
        bankBaseUrl: String,
        bankToken: String,
        consentId: String,
        clientId: String,
        accountNumber: String?
    ): String? {
        if (accountNumber.isNullOrBlank()) return null

        val getUrl = "$bankBaseUrl/cards?client_id=${clientId}-1&account_id=$accountNumber"
        try {
            val getResp = client.get(getUrl) {
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", clientId)
                header("Accept", "application/json")
            }
            val cards = mapper.readTree(getResp.bodyAsText()).path("data").path("cards")
            return cards.firstOrNull()?.path("cardId")?.asText() ?: issueNewCard(bankBaseUrl, bankToken, consentId, clientId, clientId, accountNumber)
        } catch (_: Exception) { return null }
    }

    private suspend fun issueNewCard(
        bankBaseUrl: String,
        bankToken: String,
        consentId: String,
        requestingBank: String,
        clientId: String,
        accountNumber: String?,
        cardName: String = "Visa Classic",
        cardType: String = "debit"
    ): String? {
        if (accountNumber.isNullOrBlank()) return null

        val url = "$bankBaseUrl/cards?client_id=$clientId-1"
        return try {
            val resp = client.post(url) {
                contentType(ContentType.Application.Json)
                header("Authorization", "Bearer $bankToken")
                header("X-Requesting-Bank", requestingBank)
                header("X-Consent-Id", consentId)
                setBody(mapOf("account_number" to accountNumber, "card_name" to cardName, "card_type" to cardType))
            }
            mapper.readTree(resp.bodyAsText()).path("cardId").asText(null)
        } catch (_: Exception) { null }
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
        userInput: UserInput,
        productRequestId: String? = null
    ) {
        val httpMethod = HttpMethod.parse(method)
        val consentHeaderName = when {
            url.contains("/product-agreements") -> "X-Product-Agreement-Consent-Id"
            url.contains("/cards") -> "X-Consent-Id"
            else -> "X-Consent-Id"
        }

        val response = try {
            client.request(url) {
                this.method = httpMethod
                header("Authorization", "Bearer $bankToken")
                header(consentHeaderName, consentId)
                header("X-Requesting-Bank", if (url.contains("/cards")) userInput.clientId else userInput.requestingBank)
                if (httpMethod != HttpMethod.Get) {
                    contentType(ContentType.Application.Json)
                    setBody("{}")
                }
            }
        } catch (ex: Exception) {
            issues.add(Issue("REQUEST_FAILED", Severity.MEDIUM, "$method $url → Exception: ${ex.message}"))
            return
        }

        val status = response.status.value
        val body = runCatching { response.bodyAsText() }.getOrNull()
        if (status == 403)
            issues.add(Issue("ENDPOINT_FORBIDDEN", Severity.LOW, "$method $url → 403", url, method))

        checkSensitiveFields(body, url, method, issues)
    }

    private fun checkSensitiveFields(body: String?, url: String, method: String, issues: MutableList<Issue>) {
        if (body.isNullOrBlank()) return
        val json = runCatching { mapper.readTree(body) }.getOrNull() ?: return
        val sensitive = listOf("password", "token", "secret", "ssn", "creditCard", "dob")

        fun traverse(node: JsonNode) {
            if (node.isObject) {
                node.fields().forEach { (key, value) ->
                    if (sensitive.any { key.contains(it, ignoreCase = true) }) {
                        issues.add(Issue("EXCESSIVE_DATA_EXPOSURE", Severity.HIGH, "Ответ содержит чувствительное поле: $key", url, method))
                    }
                    traverse(value)
                }
            } else if (node.isArray) node.forEach { traverse(it) }
        }
        traverse(json)
    }

    private suspend fun getFirstAccount(bankBaseUrl: String, bankToken: String, consentId: String, clientId: String): String? {
        val url = "$bankBaseUrl/accounts?client_id=${clientId}-1"
        return try {
            val response = client.request(url) {
                method = HttpMethod.Get
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", clientId)
                header("Accept", "application/json")
            }
            val accountsNode = mapper.readTree(response.bodyAsText()).path("data").path("account")
            accountsNode.firstOrNull()?.path("accountId")?.asText()
        } catch (_: Exception) { null }
    }

    private suspend fun createPaymentConsent(userInput: UserInput, bankToken: String, issues: MutableList<Issue>): String? {
        val url = "${userInput.targetUrl}/payment-consents/request"
        return try {
            val response = client.post(url) {
                contentType(ContentType.Application.Json)
                header("Authorization", "Bearer $bankToken")
                header("X-Requesting-Bank", userInput.requestingBank)
                setBody(
                    """
                    {
                      "requesting_bank": "${userInput.requestingBank}",
                      "client_id": "${userInput.clientId}-1",
                      "consent_type": "single_use",
                      "amount": 100.0,
                      "debtor_account": "",
                      "reference": "API scan payment"
                    }
                    """.trimIndent()
                )
            }
            if (response.status.value != 200) return null
            mapper.readTree(response.bodyAsText()).path("consent_id").asText(null)
        } catch (ex: Exception) {
            issues.add(Issue("PAYMENT_CONSENT_FAIL", Severity.HIGH, "Не удалось создать Payment Consent: ${ex.message}"))
            null
        }
    }

    private suspend fun createProductAgreementConsent(
        userInput: UserInput,
        bankToken: String,
        issues: MutableList<Issue>
    ): Pair<String?, String?> {
        val url = "${userInput.targetUrl}/product-agreement-consents/request?client_id=${userInput.clientId}-1"
        return try {
            val response = client.post(url) {
                contentType(ContentType.Application.Json)
                header("Authorization", "Bearer $bankToken")
                header("X-Requesting-Bank", userInput.requestingBank)
                setBody(
                    """
                    {
                      "requesting_bank": "${userInput.requestingBank}",
                      "client_id": "${userInput.clientId}-1",
                      "read_product_agreements": true,
                      "open_product_agreements": true,
                      "close_product_agreements": false,
                      "allowed_product_types": ["deposit","card"],
                      "max_amount": 1000000.00,
                      "valid_until": "2025-12-31T23:59:59",
                      "reason": "Финансовый агрегатор для управления продуктами"
                    }
                    """.trimIndent()
                )
            }
            val json = mapper.readTree(response.bodyAsText())
            json.path("consent_id").asText(null) to json.path("request_id").asText(null)
        } catch (ex: Exception) {
            issues.add(Issue("PRODUCT_CONSENT_FAIL", Severity.HIGH, "Не удалось создать Product Agreement Consent: ${ex.message}"))
            null to null
        }
    }

    private fun String.removeQueryParam(param: String): String {
        val uri = java.net.URI(this)
        val query = uri.query?.split("&")?.filterNot { it.startsWith("$param=") }?.joinToString("&")
        return java.net.URI(uri.scheme, uri.authority, uri.path, query, uri.fragment).toString()
    }
}
