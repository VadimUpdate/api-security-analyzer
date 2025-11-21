package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.client.request.*
import io.swagger.v3.oas.models.Operation
import io.swagger.v3.oas.models.parameters.HeaderParameter
import io.swagger.v3.oas.models.parameters.QueryParameter
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import org.springframework.stereotype.Service
import kotlin.random.Random

@Service
class FuzzerService(
    private val authService: AuthService
) {

    private val mapper = jacksonObjectMapper()

    private val basePayloads = listOf(
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "{\"test\":123}",
        "{\"value\":\"AAAA\"}",
        "admin",
        "null",
        "true",
        "false"
    )

    var requestsPerVector: Int = 3

    suspend fun runFuzzingPublic(
        url: String,
        operation: Operation,
        httpMethod: HttpMethod,
        clientId: String,
        clientSecret: String,
        consentId: String,
        issues: MutableList<Issue>
    ) {
        runFuzzing(url, operation, httpMethod, clientId, clientSecret, consentId, issues)
    }

    suspend fun runFuzzingForAllEndpoints(
        operations: List<Triple<String, String, Operation>>,
        clientId: String,
        clientSecret: String,
        consentId: String
    ): List<Issue> {
        val allIssues = mutableListOf<Issue>()
        coroutineScope {
            operations.map { (url, method, op) ->
                async {
                    val httpMethod = extractMethod(method)
                    runFuzzing(url, op, httpMethod, clientId, clientSecret, consentId, allIssues)
                }
            }.awaitAll()
        }
        return allIssues
    }

    private suspend fun runFuzzing(
        url: String,
        operation: Operation,
        httpMethod: HttpMethod,
        clientId: String,
        clientSecret: String,
        consentId: String,
        issues: MutableList<Issue>
    ) {
        val payloads = generatePayloads()

        // QUERY
        operation.parameters
            ?.filterIsInstance<QueryParameter>()
            ?.forEach { param ->
                repeat(requestsPerVector) {
                    val payload = payloads.random()
                    val fuzzed = appendQuery(url, param.name, payload)
                    sendFuzzedRequest(
                        fuzzed,
                        httpMethod,
                        null,
                        clientId,
                        clientSecret,
                        consentId,
                        issues,
                        "query:${param.name}",
                        payload,
                        null
                    )
                }
            }

        // HEADERS
        operation.parameters
            ?.filterIsInstance<HeaderParameter>()
            ?.forEach { param ->
                repeat(requestsPerVector) {
                    val payload = payloads.random()
                    sendFuzzedRequest(
                        url,
                        httpMethod,
                        null,
                        clientId,
                        clientSecret,
                        consentId,
                        issues,
                        "header:${param.name}",
                        payload,
                        param.name to payload
                    )
                }
            }

        // BODY JSON
        val bodySchema = operation.requestBody?.content?.values?.firstOrNull()?.schema
        if (bodySchema != null) {
            val baseJson = buildSampleJsonFromSchema(bodySchema)
            repeat(requestsPerVector) {
                val payload = payloads.random()
                val fuzzedBody = mutateJsonFull(baseJson.deepCopy(), payload)
                sendFuzzedRequest(
                    url,
                    httpMethod,
                    fuzzedBody,
                    clientId,
                    clientSecret,
                    consentId,
                    issues,
                    "body",
                    payload,
                    null
                )
            }
        }
    }

    private suspend fun sendFuzzedRequest(
        url: String,
        method: HttpMethod,
        body: JsonNode? = null,
        clientId: String,
        clientSecret: String,
        consentId: String,
        issues: MutableList<Issue>,
        vector: String,
        payload: String,
        extraHeader: Pair<String, String>? = null
    ) {
        println("=== FUZZ REQUEST ===")
        println("URL: $url")
        println("METHOD: $method")
        println("VECTOR: $vector")
        println("PAYLOAD: $payload")
        extraHeader?.let { println("EXTRA HEADER: ${it.first}=${it.second}") }
        println("BODY: ${body?.toPrettyString() ?: "<empty>"}")
        println("====================")

        try {
            val response: HttpResponse = authService.performRequestWithAuth(
                method = method,
                url = url,
                clientId = clientId,
                clientSecret = clientSecret,
                consentId = consentId,
                issues = issues,
                bodyBlock = {
                    extraHeader?.let { header(it.first, it.second) }
                    body?.let {
                        setBody(mapper.writeValueAsString(it))
                        contentType(ContentType.Application.Json)
                    }
                }
            )

            val bodyText = runCatching { response.bodyAsText() }.getOrElse { "" }

            // --- Логируем ВСЕ >=500 ---
            if (response.status.value >= 500) {
                issues.add(
                    Issue(
                        type = "SERVER_ERROR",
                        severity = Severity.CRITICAL,
                        description = "Сервер вернул ${response.status.value} при фуззинге ($vector)",
                        url = url,
                        method = method.value,
                        evidence = "payload=$payload\nresponse=$bodyText",
                        recommendation = "Проверить обработку ошибок на сервере."
                    )
                )
            }

            // Нормальная запись результата фуззинга
            issues.add(
                Issue(
                    type = "FUZZ_${vector.uppercase()}",
                    severity = if (response.status.isSuccess()) Severity.LOW else Severity.MEDIUM,
                    description = "Fuzz payload '$payload' → HTTP ${response.status.value}",
                    url = url,
                    method = method.value,
                    evidence = "payload=$payload"
                )
            )

        } catch (ex: Exception) {

            // Игнорируем ошибки "Требуется токен/consentId..." (не добавляем issue)
            val msg = ex.message ?: ""
            if (msg.contains("Требуется токен", ignoreCase = true) ||
                msg.contains("consentId", ignoreCase = true)
            ) {
                return
            }

            // Остальные исключения логируем
            issues.add(
                Issue(
                    type = "FUZZ_EXCEPTION",
                    severity = Severity.HIGH,
                    description = "Exception during fuzzing",
                    url = url,
                    method = method.value,
                    evidence = "${ex.message} | payload=$payload"
                )
            )
        }
    }

    private fun generatePayloads(): List<String> {
        val r = mutableListOf<String>()
        for (p in basePayloads) {
            r += p
            r += mutateDeleteFragment(p)
            r += mutateInvertFragment(p)
            r += mutateDuplicateFragment(p)
            r += mutateBinaryBlob(p)
            r += p.reversed()
            r += p.uppercase()
            r += p.lowercase()
        }
        return r.distinct()
    }

    private fun mutateDeleteFragment(input: String): String {
        if (input.length < 4) return input
        val start = Random.nextInt(0, input.length / 2)
        val end = Random.nextInt(start + 1, input.length)
        return input.removeRange(start, end)
    }

    private fun mutateInvertFragment(input: String): String {
        if (input.length < 4) return input
        val start = Random.nextInt(0, input.length / 2)
        val end = Random.nextInt(start + 2, input.length)
        val fragment = input.substring(start, end).reversed()
        return input.replaceRange(start, end, fragment)
    }

    private fun mutateDuplicateFragment(input: String): String {
        if (input.length < 3) return input
        val start = Random.nextInt(0, input.length - 1)
        val end = Random.nextInt(start + 1, input.length)
        val fragment = input.substring(start, end)
        return input + fragment
    }

    private fun mutateBinaryBlob(input: String): String {
        val blob = ByteArray(16) { Random.nextInt(0, 255).toByte() }
        val blobStr = blob.joinToString("") { "\\x" + it.toUByte().toString(16).padStart(2, '0') }
        return input + blobStr
    }

    private fun buildSampleJsonFromSchema(schema: io.swagger.v3.oas.models.media.Schema<*>): JsonNode {
        val node = mapper.createObjectNode()
        schema.properties?.forEach { (k, v) ->
            when (v.type) {
                "string" -> node.put(k, "sample")
                "integer" -> node.put(k, 1)
                "number" -> node.put(k, 1.0)
                "boolean" -> node.put(k, true)
                "object" -> node.set<JsonNode>(k, buildSampleJsonFromSchema(v))
                else -> node.put(k, "sample")
            }
        }
        return node
    }

    private fun mutateJsonFull(root: JsonNode, payload: String): JsonNode {
        if (!root.isObject) return root
        val obj = root.deepCopy<ObjectNode>()
        obj.fieldNames().forEachRemaining { k ->
            obj.put(k, payload)
        }
        return obj
    }

    private fun appendQuery(url: String, key: String, value: String): String {
        val encoded = java.net.URLEncoder.encode(value, Charsets.UTF_8)
        return if ("?" in url) "$url&$key=$encoded" else "$url?$key=$encoded"
    }

    private fun extractMethod(httpMethod: String): HttpMethod = when (httpMethod.uppercase()) {
        "GET" -> HttpMethod.Get
        "POST" -> HttpMethod.Post
        "PUT" -> HttpMethod.Put
        "DELETE" -> HttpMethod.Delete
        "PATCH" -> HttpMethod.Patch
        "OPTIONS" -> HttpMethod.Options
        else -> HttpMethod.Get
    }
}
