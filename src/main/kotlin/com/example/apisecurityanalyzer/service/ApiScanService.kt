package com.example.apianalyzer.service

import com.example.apianalyzer.model.*
import com.example.apianalyzer.plugin.BuiltinCheckersPlugin
import com.example.apianalyzer.plugin.PluginRegistry
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

        val accountConsentId = if (!bankToken.isNullOrBlank()) {
            consentService.createAccountConsent(userInput, bankToken, issues)
        } else null

        if (accountConsentId.isNullOrBlank() && !bankToken.isNullOrBlank())
            issues.add(Issue("CONSENT_FAIL", Severity.HIGH, "Account consent не получен или не одобрен"))

        val paymentConsentId = if (!bankToken.isNullOrBlank()) {
            consentService.createPaymentConsent(userInput, bankToken, issues)
        } else null

        if (paymentConsentId.isNullOrBlank() && !bankToken.isNullOrBlank())
            issues.add(Issue("PAYMENT_CONSENT_FAIL", Severity.HIGH, "Payment consent не получен или не одобрен"))

        var productRequestId: String? = null
        val productConsentId = if (!bankToken.isNullOrBlank()) {
            val pair = consentService.createProductAgreementConsent(userInput, bankToken, issues)
            productRequestId = pair.second
            pair.first
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

        // === Исправлено ===
        plugin.bankToken = bankToken ?: ""
        plugin.consentId = paymentConsentId ?: accountConsentId ?: productConsentId ?: ""

        val pluginRegistry = PluginRegistry().apply { register(plugin) }

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

                    val combinedParams: List<Parameter> =
                        (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())

                    val url = when {
                        pathTemplate.contains("{account_id}") && accountId != null ->
                            buildUrlFromPath(userInput.targetUrl, pathTemplate.replace("{account_id}", accountId), combinedParams)
                                .removeQueryParam("client_id")

                        pathTemplate.startsWith("/cards") ->
                            cardService.handleCardPaths(pathTemplate, userInput, combinedParams, accountNumber, cardId, accountConsentId, bankToken)

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
                                    val consentToUse = consentService.selectConsentForPath(url, paymentConsentId, productConsentId, accountConsentId)
                                    if (!consentToUse.isNullOrBlank())
                                        consentService.performEnhancedChecks(url, method, issues, bankToken, consentToUse, userInput, productRequestId)
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
}
