package com.example.apianalyzer.service

import com.example.apianalyzer.model.*
import com.example.apianalyzer.plugin.*
import com.fasterxml.jackson.databind.JsonNode
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
    private val clientProvider: ClientProvider,
    private val authService: AuthService,
    private val consentService: ConsentService,
    private val fuzzerService: FuzzerService
) {

    private val mapper = jacksonObjectMapper()
    private val client get() = clientProvider.client

    fun runScan(userInput: UserInput): ScanReport = runBlocking {
        val issues = mutableListOf<Issue>()

        // Загрузка спецификации OpenAPI
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

        // Получение токена
        val openIdToken = try {
            authService.getOpenIdToken(userInput.clientId, userInput.clientSecret, issues)
        } catch (e: Exception) {
            issues.add(Issue("AUTH_TOKEN_FAIL", Severity.HIGH, "Не удалось получить OpenID token: ${e.message}"))
            null
        }

        // Получение consents через create*Consent
        val accountConsentId = consentService.createAccountConsent(userInput, openIdToken ?: "", issues)
        val paymentConsentId = consentService.createPaymentConsent(userInput, openIdToken ?: "", issues)
        val productConsentId = consentService.createProductAgreementConsent(userInput, openIdToken ?: "", issues).first

        // ---------------------------
        // ПЛАГИНЫ
        // ---------------------------
        val plugins: List<CheckerPlugin> = listOf(
            BrokenAuthCheckerPlugin(clientProvider, consentService, userInput, openIdToken ?: ""),
            BOLACheckerPlugin(clientProvider, consentService, fuzzerService, userInput, openIdToken ?: "",
                consentService.selectConsentForPath("", paymentConsentId, productConsentId, accountConsentId) ?: ""),
            IDORCheckerPlugin(clientProvider, consentService, userInput, openIdToken ?: ""),
            MassAssignmentCheckerPlugin(clientProvider, consentService, userInput),
            InjectionCheckerPlugin(clientProvider, consentService, userInput),
            SensitiveFilesCheckerPlugin(clientProvider, consentService, userInput, openIdToken ?: "")
        )

        val semaphore = Semaphore(userInput.maxConcurrency)

        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()

            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)
                for ((method, operation) in operations) {
                    if (operation == null) continue

                    val combinedParams: List<Parameter> =
                        (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())

                    val url = buildUrlFromPath(userInput.targetUrl, pathTemplate, combinedParams)

                    jobs.add(async {
                        semaphore.withPermit {
                            delay(userInput.politenessDelayMs.toLong())
                            try {
                                val body = generateValidRequestBody(operation, userInput)
                                performRequestWithAuth(url, method, body, openIdToken, issues, userInput.useGostGateway)

                                plugins.forEach { plugin ->
                                    plugin.runCheck(url, method, operation, issues)
                                }

                                fuzzerService.runFuzzing(
                                    url,
                                    operation,
                                    userInput.clientId,
                                    userInput.clientSecret,
                                    consentService.selectConsentForPath(url, paymentConsentId, productConsentId, accountConsentId) ?: "",
                                    issues
                                )
                            } catch (ex: Exception) {
                                issues.add(Issue("SCAN_ERROR", Severity.MEDIUM, "Ошибка при запросе $url: ${ex.message}"))
                            }
                            Unit // <- добавить здесь
                        }
                    })

                }
            }
            jobs.awaitAll()
        }

        // Глобальные проверки
        if (userInput.enableRateLimiting || userInput.enableSensitiveFiles || userInput.enablePublicSwagger) {
            runGlobalChecks(client, userInput.targetUrl, issues, userInput)
        }

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
            accountIds = emptyList()
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

    private fun generateValidRequestBody(operation: io.swagger.v3.oas.models.Operation, userInput: UserInput): JsonNode? {
        val schema = operation.requestBody?.content?.values?.firstOrNull()?.schema ?: return null
        return buildSampleJsonFromSchema(schema, userInput)
    }

    private suspend fun performRequestWithAuth(
        url: String,
        method: String,
        body: JsonNode?,
        token: String?,
        issues: MutableList<Issue>,
        useGostGateway: Boolean
    ) {
        try {
            if (useGostGateway) {
                if (token.isNullOrBlank()) return
                executeGostCurl(url, method, token, body)
            } else {
                client.request(url) {
                    this.method = HttpMethod.parse(method)
                    if (body != null) {
                        contentType(ContentType.Application.Json)
                        setBody(body.toString())
                    }
                    if (!token.isNullOrBlank()) header("Authorization", "Bearer $token")
                }
            }
        } catch (ex: ClientRequestException) {
            issues.add(Issue("SPEC_MISMATCH", Severity.MEDIUM, "Ответ не соответствует спецификации: ${ex.response.status.value}"))
        } catch (ex: Exception) {
            issues.add(Issue("REQUEST_FAIL", Severity.MEDIUM, "Ошибка запроса: ${ex.message}"))
        }
    }

    private fun buildSampleJsonFromSchema(schema: io.swagger.v3.oas.models.media.Schema<*>, userInput: UserInput): JsonNode {
        val node = mapper.createObjectNode()
        schema.properties?.forEach { (key, prop) ->
            when (prop.type) {
                "string" -> node.put(
                    key, when (key.lowercase()) {
                        "client_id" -> userInput.clientId
                        "bank" -> userInput.requestingBank
                        else -> "sample"
                    }
                )
                "integer" -> node.put(key, 1)
                "number" -> node.put(key, 1.0)
                "boolean" -> node.put(key, true)
                "object" -> node.set<JsonNode>(key, buildSampleJsonFromSchema(prop, userInput))
                else -> node.put(key, "sample")
            }
        }
        return node
    }

    private fun executeGostCurl(url: String, method: String, token: String, body: JsonNode?): String {
        val cmd = mutableListOf(
            "curl", "-v", "-k",
            "-X", method,
            "-H", "Authorization: Bearer $token",
            "-H", "Content-Type: application/json",
            url
        )
        if (body != null) cmd.addAll(listOf("-d", body.toString()))

        val process = ProcessBuilder(cmd).start()
        val result = StringBuilder()
        BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
            reader.forEachLine { result.append(it).append("\n") }
        }
        process.waitFor()
        return result.toString()
    }
}

// ----------------------
// ГЛОБАЛЬНЫЕ ПРОВЕРКИ
// ----------------------
suspend fun runGlobalChecks(
    client: io.ktor.client.HttpClient,
    baseUrl: String,
    issues: MutableList<Issue>,
    userInput: UserInput
) {
    if (userInput.enableRateLimiting) checkRateLimiting(client, baseUrl, issues)
    if (userInput.enableSensitiveFiles) checkSensitiveFiles(client, baseUrl, issues)
    if (userInput.enablePublicSwagger) checkPublicSwagger(client, baseUrl, issues)
}

suspend fun checkRateLimiting(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
suspend fun checkSensitiveFiles(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
suspend fun checkPublicSwagger(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
