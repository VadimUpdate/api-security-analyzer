package com.example.apianalyzer.service

import com.example.apianalyzer.model.*
import com.example.apianalyzer.plugin.*
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.media.Schema
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
        val observedResponses = mutableMapOf<String, MutableSet<Int>>()  // URL → set(statusCode)

        // ----------------------
        // Load & Parse Spec
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
                                val requestBody = generateValidRequestBody(operation, userInput)
                                val rawResponse = performRawRequest(url, methodStr, requestBody, openIdToken, issues, userInput.useGostGateway)

                                if (rawResponse != null) {
                                    observedResponses.getOrPut(url) { mutableSetOf() }.add(rawResponse.status)

                                    val jsonBody = rawResponse.body
                                    validateStatusCode(operation, rawResponse.status, url, methodStr, issues)
                                    if (jsonBody != null) {
                                        validateResponseRecursive(jsonBody, operation, url, methodStr, issues)
                                    }
                                }

                                // ----------------------
                                // Plugins
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
                            return@withPermit Unit
                        }
                    })
                }
            }
            jobs.awaitAll()
        }

        // ----------------------
        // Global checks
        // ----------------------
        if (userInput.enableRateLimiting || userInput.enableSensitiveFiles || userInput.enablePublicSwagger) {
            runGlobalChecks(client, userInput.targetUrl, issues, userInput)
        }

        // ----------------------
        // Shadow endpoints
        // ----------------------
        if (userInput.enableSpecChecks) {
            detectShadowEndpoints(
                observedEndpoints,
                observedResponses,
                pathsMap,
                userInput,
                issues
            )
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

    // ---------------------------------------------------------
    // REQUEST EXECUTION
    // ---------------------------------------------------------

    private data class RawResponse(val status: Int, val body: JsonNode?)

    private suspend fun performRawRequest(
        url: String,
        method: String,
        body: JsonNode?,
        token: String?,
        issues: MutableList<Issue>,
        useGostGateway: Boolean
    ): RawResponse? {
        return try {
            val (status, text) =
                if (useGostGateway) {
                    if (token.isNullOrBlank()) return null
                    val raw = executeGostCurl(url, method, token, body)
                    200 to raw // GOST gateway does not return code
                } else {
                    val resp = client.request(url) {
                        this.method = HttpMethod.parse(method)
                        if (body != null) {
                            contentType(ContentType.Application.Json)
                            setBody(body.toString())
                        }
                        if (!token.isNullOrBlank()) header("Authorization", "Bearer $token")
                    }
                    resp.status.value to resp.bodyAsText()
                }

            val parsedBody = try {
                if (!text.isNullOrBlank()) mapper.readTree(text) else null
            } catch (_: Exception) {
                null
            }

            RawResponse(status, parsedBody)

        } catch (ex: Exception) {
            issues.add(Issue("REQUEST_FAIL", Severity.MEDIUM, "Не удалось выполнить запрос: ${ex.message}", url, method))
            null
        }
    }

    // ---------------------------------------------------------
    // FULL CONTRACT VALIDATION
    // ---------------------------------------------------------

    private fun validateStatusCode(
        operation: io.swagger.v3.oas.models.Operation,
        actualStatus: Int,
        url: String,
        method: String,
        issues: MutableList<Issue>
    ) {
        val declared = operation.responses?.keys?.mapNotNull { it.toIntOrNull() }?.toSet() ?: emptySet()

        if (declared.isNotEmpty() && actualStatus !in declared) {
            issues.add(
                Issue(
                    type = "UNDECLARED_STATUS_CODE",
                    severity = Severity.MEDIUM,
                    description = "Код ответа $actualStatus отсутствует в спецификации",
                    url = url,
                    method = method,
                    evidence = "Declared: $declared",
                    recommendation = "Добавить код ответа в спецификацию или исправить ответ API"
                )
            )
        }
    }

    private fun validateResponseRecursive(
        response: JsonNode,
        operation: io.swagger.v3.oas.models.Operation,
        url: String,
        method: String,
        issues: MutableList<Issue>
    ) {
        val schema = operation.responses?.get("200")?.content?.values?.firstOrNull()?.schema ?: return
        checkSchemaRecursive(response, schema, "$url [$method]", issues)
    }

    private fun checkSchemaRecursive(
        node: JsonNode,
        schema: Schema<*>,
        context: String,
        issues: MutableList<Issue>
    ) {
        when (schema.type) {
            "object" -> {
                if (!node.isObject) {
                    issues.add(
                        Issue(
                            "TYPE_MISMATCH",
                            Severity.MEDIUM,
                            "Ожидался объект в $context",
                            url = context,
                            method = null,
                            evidence = node.toString()
                        )
                    )
                    return
                }
                val obj = node as ObjectNode
                val props = schema.properties ?: emptyMap()

                // missing required
                schema.required?.forEach { req ->
                    if (!obj.has(req)) {
                        issues.add(
                            Issue(
                                "MISSING_REQUIRED_FIELD",
                                Severity.MEDIUM,
                                "Отсутствует обязательное поле '$req' в $context",
                                url = context,
                                method = null
                            )
                        )
                    }
                }

                // extra fields
                obj.fieldNames().forEach { field ->
                    if (!props.containsKey(field)) {
                        issues.add(
                            Issue(
                                "EXTRA_FIELD",
                                Severity.LOW,
                                "Поле '$field' отсутствует в спецификации",
                                url = context,
                                method = null,
                                evidence = obj[field].toString()
                            )
                        )
                    }
                }

                // recursively validate children
                props.forEach { (name, propSchema) ->
                    if (obj.has(name)) {
                        checkSchemaRecursive(obj[name], propSchema, "$context.$name", issues)
                    }
                }
            }

            "array" -> {
                if (!node.isArray) {
                    issues.add(
                        Issue(
                            "TYPE_MISMATCH",
                            Severity.MEDIUM,
                            "Ожидался массив в $context",
                            url = context,
                            method = null,
                            evidence = node.toString()
                        )
                    )
                    return
                }
                val items = (node as ArrayNode)
                val itemSchema = schema.items ?: return
                items.forEachIndexed { i, child ->
                    checkSchemaRecursive(child, itemSchema, "$context[$i]", issues)
                }
            }

            "string" -> if (!node.isTextual)
                issues.add(typeErr(context, "string", node))

            "integer" -> if (!node.isInt)
                issues.add(typeErr(context, "integer", node))

            "number" -> if (!node.isNumber)
                issues.add(typeErr(context, "number", node))

            "boolean" -> if (!node.isBoolean)
                issues.add(typeErr(context, "boolean", node))
        }
    }

    private fun typeErr(ctx: String, expected: String, actual: JsonNode) =
        Issue(
            "TYPE_MISMATCH",
            Severity.MEDIUM,
            "Неверный тип. Ожидается $expected в $ctx",
            url = ctx,
            method = null,
            evidence = actual.toString()
        )

    // ---------------------------------------------------------
    // SHADOW ENDPOINTS
    // ---------------------------------------------------------
    private fun detectShadowEndpoints(
        observed: Set<String>,
        responses: Map<String, Set<Int>>,
        pathsMap: Map<String, *>,
        userInput: UserInput,
        issues: MutableList<Issue>
    ) {
        val declaredPatterns = pathsMap.keys.toList()

        observed.forEach { url ->
            val path = url.removePrefix(userInput.targetUrl)

            val matchesSpec = declaredPatterns.any { pattern ->
                val regex = pattern.replace("{", "\\{").replace("}", "\\}").replace("\\{[^/]+\\}".toRegex(), "[^/]+")
                    .let { Regex("^$it$") }
                regex.matches(path)
            }

            if (!matchesSpec) {
                val codes = responses[url] ?: emptySet()
                if (codes.any { it != 404 && it != 405 }) {
                    issues.add(
                        Issue(
                            type = "SHADOW_ENDPOINT",
                            severity = Severity.HIGH,
                            description = "Endpoint '$url' не описан в спецификации, но отвечает",
                            url = url,
                            method = null,
                            evidence = codes.joinToString(),
                            recommendation = "Проверьте необходимость этого эндпоинта"
                        )
                    )
                }
            }
        }
    }

    // ---------------------------------------------------------
    // UTILITIES
    // ---------------------------------------------------------

    private fun generateValidRequestBody(operation: io.swagger.v3.oas.models.Operation, userInput: UserInput): JsonNode? {
        val schema = operation.requestBody?.content?.values?.firstOrNull()?.schema ?: return null
        return buildSampleJsonFromSchema(schema, userInput)
    }

    private fun buildSampleJsonFromSchema(schema: Schema<*>, userInput: UserInput): ObjectNode {
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
// Global Checks
// ----------------------
suspend fun runGlobalChecks(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>, userInput: UserInput) {
    if (userInput.enableRateLimiting) checkRateLimiting(client, baseUrl, issues)
    if (userInput.enableSensitiveFiles) checkSensitiveFiles(client, baseUrl, issues)
    if (userInput.enablePublicSwagger) checkPublicSwagger(client, baseUrl, issues)
}

suspend fun checkRateLimiting(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
suspend fun checkSensitiveFiles(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
suspend fun checkPublicSwagger(client: io.ktor.client.HttpClient, baseUrl: String, issues: MutableList<Issue>) {}
