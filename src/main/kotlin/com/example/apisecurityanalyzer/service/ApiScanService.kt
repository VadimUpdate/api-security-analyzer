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
import kotlin.random.Random

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
        val observedEndpoints = mutableSetOf<String>()

        // ----------------------
        // Загрузка и парсинг OpenAPI
        // ----------------------
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

        val openIdToken = try {
            authService.getOpenIdToken(userInput.clientId, userInput.clientSecret, issues)
        } catch (e: Exception) {
            issues.add(Issue("AUTH_TOKEN_FAIL", Severity.HIGH, "Не удалось получить OpenID token: ${e.message}"))
            null
        }

        val accountConsentId = consentService.createAccountConsent(userInput, openIdToken ?: "", issues)
        val paymentConsentId = consentService.createPaymentConsent(userInput, openIdToken ?: "", issues)
        val productConsentId = consentService.createProductAgreementConsent(userInput, openIdToken ?: "", issues).first

        val semaphore = Semaphore(userInput.maxConcurrency)

        coroutineScope {
            val jobs = mutableListOf<Deferred<Unit>>()
            for ((pathTemplate, pathItem) in pathsMap) {
                val operations = extractOperations(pathItem)
                for ((methodStr, operation) in operations) {
                    if (operation == null) continue

                    val combinedParams: List<Parameter> =
                        (pathItem.parameters ?: emptyList()) + (operation.parameters ?: emptyList())
                    val url = buildUrlFromPath(userInput.targetUrl, pathTemplate, combinedParams)
                    observedEndpoints += url
                    val httpMethod = HttpMethod.parse(methodStr)

                    jobs.add(async {
                        semaphore.withPermit {
                            delay(userInput.politenessDelayMs.toLong())
                            try {
                                val body = generateValidRequestBody(operation, userInput)
                                val responseBody = performRequestAndGetBody(url, methodStr, body, openIdToken, issues, userInput.useGostGateway)

                                // ----------------------
                                // Проверка соответствия спецификации
                                // ----------------------
                                if (responseBody != null) {
                                    validateResponseAgainstSchema(responseBody, operation, url, methodStr, issues)
                                    validateResponseTypes(responseBody, operation, url, methodStr, issues)
                                    detectExcessiveData(responseBody, operation, url, methodStr, issues)
                                }

                                // ----------------------
                                // Вызов плагинов
                                // ----------------------
                                if (userInput.enableBrokenAuth) {
                                    BrokenAuthCheckerPlugin(clientProvider, consentService, userInput, openIdToken ?: "")
                                        .runCheck(url, methodStr, operation, issues)
                                }
                                if (userInput.enableBOLA) {
                                    BOLACheckerPlugin(
                                        clientProvider,
                                        consentService,
                                        fuzzerService,
                                        userInput,
                                        openIdToken ?: "",
                                        consentService.selectConsentForPath(url, paymentConsentId, productConsentId, accountConsentId) ?: ""
                                    ).runCheck(url, methodStr, operation, issues)
                                }
                                if (userInput.enableIDOR) {
                                    IDORCheckerPlugin(clientProvider, consentService, userInput, openIdToken ?: "")
                                        .runCheck(url, methodStr, operation, issues)
                                }
                                if (userInput.enableMassAssignment) {
                                    MassAssignmentCheckerPlugin(clientProvider, consentService, userInput)
                                        .runCheck(url, methodStr, operation, issues)
                                }
                                if (userInput.enableInjection) {
                                    InjectionCheckerPlugin(clientProvider, consentService, userInput)
                                        .runCheck(url, methodStr, operation, issues)
                                }
                                if (userInput.enableSensitiveFiles) {
                                    SensitiveFilesCheckerPlugin(clientProvider, consentService, userInput, openIdToken ?: "")
                                        .runCheck(url, methodStr, operation, issues)
                                }
                                if (userInput.enableFuzzing) {
                                    fuzzerService.runFuzzingPublic(
                                        url = url,
                                        operation = operation,
                                        httpMethod = httpMethod,
                                        clientId = userInput.clientId,
                                        clientSecret = userInput.clientSecret,
                                        consentId = consentService.selectConsentForPath(url, paymentConsentId, productConsentId, accountConsentId) ?: "",
                                        issues = issues
                                    )
                                }

                            } catch (ex: Exception) {
                                issues.add(Issue("SCAN_ERROR", Severity.MEDIUM, "Ошибка при запросе $url: ${ex.message}"))
                            }
                            Unit
                        }
                    })
                }
            }
            jobs.awaitAll()
        }

        // ----------------------
        // Глобальные проверки
        // ----------------------
        if (userInput.enableRateLimiting || userInput.enableSensitiveFiles || userInput.enablePublicSwagger) {
            runGlobalChecks(client, userInput.targetUrl, issues, userInput)
        }

        // ----------------------
        // Неописанные эндпоинты
        // ----------------------
        if (userInput.enableSpecChecks) {
            val knownUrls = pathsMap.flatMap { (template, pi) ->
                extractOperations(pi).mapNotNull { (method, _) ->
                    buildUrlFromPath(userInput.targetUrl, template, pi.parameters ?: emptyList())
                }
            }.toSet()
            val unknownEndpoints = observedEndpoints - knownUrls
            unknownEndpoints.forEach { url ->
                issues.add(
                    Issue(
                        type = "POTENTIAL_SPECMATCH",
                        severity = Severity.MEDIUM,
                        description = "Обнаружен эндпоинт не описанный в спецификации",
                        url = url,
                        method = null,
                        evidence = null,
                        recommendation = "Проверить, стоит ли добавить эндпоинт в спецификацию или он лишний"
                    )
                )
            }
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

    private suspend fun performRequestAndGetBody(
        url: String,
        method: String,
        body: JsonNode?,
        token: String?,
        issues: MutableList<Issue>,
        useGostGateway: Boolean
    ): JsonNode? {
        return try {
            val text = if (useGostGateway) {
                if (token.isNullOrBlank()) return null
                executeGostCurl(url, method, token, body)
            } else {
                client.request(url) {
                    this.method = HttpMethod.parse(method)
                    if (body != null) {
                        contentType(ContentType.Application.Json)
                        setBody(body.toString())
                    }
                    if (!token.isNullOrBlank()) header("Authorization", "Bearer $token")
                }.bodyAsText()
            }
            mapper.readTree(text)
        } catch (ex: Exception) {
            issues.add(Issue("REQUEST_FAIL", Severity.MEDIUM, "Не удалось получить или распарсить ответ: ${ex.message}", url, method))
            null
        }
    }

    private fun validateResponseAgainstSchema(
        response: JsonNode,
        operation: io.swagger.v3.oas.models.Operation,
        url: String,
        method: String,
        issues: MutableList<Issue>
    ) {
        val schema = operation.responses?.get("200")?.content?.values?.firstOrNull()?.schema ?: return
        checkMissingFields(response, schema, url, method, issues)
    }

    private fun validateResponseTypes(
        response: JsonNode,
        schemaOwner: io.swagger.v3.oas.models.Operation,
        url: String,
        method: String,
        issues: MutableList<Issue>
    ) {
        val schema = schemaOwner.responses?.get("200")?.content?.values?.firstOrNull()?.schema ?: return
        schema.properties?.forEach { (k, prop) ->
            if (response.has(k)) {
                val value = response[k]
                val mismatch = when (prop.type) {
                    "string" -> !value.isTextual
                    "integer" -> !value.isInt
                    "number" -> !value.isDouble && !value.isInt
                    "boolean" -> !value.isBoolean
                    "object" -> !value.isObject
                    else -> false
                }
                if (mismatch) {
                    issues.add(
                        Issue(
                            type = "POTENTIAL_TYPE_MISMATCH",
                            severity = Severity.MEDIUM,
                            description = "Неверный тип поля '$k', ожидается ${prop.type}",
                            url = url,
                            method = method,
                            evidence = value.toString(),
                            recommendation = "Исправьте тип данных поля '$k' в API или спецификации"
                        )
                    )
                }
            }
        }
    }

    private fun detectExcessiveData(
        response: JsonNode,
        schemaOwner: io.swagger.v3.oas.models.Operation,
        url: String,
        method: String,
        issues: MutableList<Issue>
    ) {
        val schema = schemaOwner.responses?.get("200")?.content?.values?.firstOrNull()?.schema ?: return
        response.fieldNames().asSequence().forEach { field ->
            if (schema.properties?.containsKey(field) != true) {
                issues.add(
                    Issue(
                        type = "POTENTIAL_EXCESS_DATA",
                        severity = Severity.LOW,
                        description = "Поле '$field' присутствует в ответе, но отсутствует в спецификации",
                        url = url,
                        method = method,
                        evidence = response[field].toString(),
                        recommendation = "Удалить лишние данные из ответа или добавить поле в спецификацию"
                    )
                )
            }
        }
    }

    private fun checkMissingFields(
        response: JsonNode,
        schema: io.swagger.v3.oas.models.media.Schema<*>,
        url: String,
        method: String,
        issues: MutableList<Issue>
    ) {
        schema.required?.forEach { field ->
            if (!response.has(field)) {
                issues.add(
                    Issue(
                        type = "POTENTIAL_MISSING_FIELD",
                        severity = Severity.MEDIUM,
                        description = "Отсутствует обязательное поле '$field'",
                        url = url,
                        method = method,
                        evidence = null,
                        recommendation = "Добавьте поле '$field' в ответ API или обновите спецификацию"
                    )
                )
            }
        }
    }

    private fun buildSampleJsonFromSchema(schema: io.swagger.v3.oas.models.media.Schema<*>, userInput: UserInput): ObjectNode {
        val node = mapper.createObjectNode()
        schema.properties?.forEach { (key, prop) ->
            when (prop.type) {
                "string" -> node.put(key, when (key.lowercase()) {
                    "client_id" -> userInput.clientId
                    "bank" -> userInput.requestingBank
                    else -> "sample"
                })
                "integer" -> node.put(key, 1)
                "number" -> node.put(key, 1.0)
                "boolean" -> node.put(key, true)
                "object" -> node.set<JsonNode>(key, buildSampleJsonFromSchema(prop, userInput))
                else -> node.put(key, "sample")
            }
        }
        return node
    }

    private fun buildUrlFromPath(base: String, template: String, params: List<Parameter>): String {
        var u = template
        params.filter { it.`in` == "path" }.forEach { u = u.replace("{${it.name}}", Random.nextInt(1, 99).toString()) }
        return base.trimEnd('/') + u
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
// Глобальные проверки
// ----------------------
suspend fun runGlobalChecks(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>, userInput: UserInput) {
    if (userInput.enableRateLimiting) checkRateLimiting(client, baseUrl, issues)
    if (userInput.enableSensitiveFiles) checkSensitiveFiles(client, baseUrl, issues)
    if (userInput.enablePublicSwagger) checkPublicSwagger(client, baseUrl, issues)
}

suspend fun checkRateLimiting(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
suspend fun checkSensitiveFiles(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
suspend fun checkPublicSwagger(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
