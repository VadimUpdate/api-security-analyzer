package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation
import io.swagger.v3.oas.models.parameters.HeaderParameter
import io.swagger.v3.oas.models.parameters.QueryParameter
import kotlinx.coroutines.*
import org.springframework.stereotype.Service
import kotlin.random.Random
import io.ktor.client.request.*

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

    // Количество запросов на каждый эндпоинт/тип ввода (query/header/body)
    var requestsPerVector: Int = 5

    suspend fun runFuzzingForAllEndpoints(
        operations: List<Pair<String, Operation>>,
        clientId: String,
        clientSecret: String,
        consentId: String
    ): List<Issue> {
        val allIssues = mutableListOf<Issue>()
        coroutineScope {
            operations.map { (url, op) ->
                async {
                    runFuzzing(url, op, clientId, clientSecret, consentId, allIssues)
                }
            }.awaitAll()
        }
        return allIssues
    }

    suspend fun runFuzzing(
        url: String,
        operation: Operation,
        clientId: String,
        clientSecret: String,
        consentId: String,
        issues: MutableList<Issue>
    ) {
        val method = operation.operationId ?: "GET"
        val payloads = generatePayloads()

        // --- fuzz query parameters ---
        operation.parameters
            ?.filterIsInstance<QueryParameter>()
            ?.forEach { param ->
                repeat(requestsPerVector) {
                    val payload = payloads.random()
                    val fuzzedUrl = appendQuery(url, param.name, payload)
                    sendFuzzedRequest(
                        fuzzedUrl,
                        method,
                        null,
                        clientId,
                        clientSecret,
                        consentId,
                        issues,
                        "query:${param.name}",
                        payload
                    )
                }
            }

        // --- fuzz headers ---
        operation.parameters
            ?.filterIsInstance<HeaderParameter>()
            ?.forEach { param ->
                repeat(requestsPerVector) {
                    val payload = payloads.random()
                    sendFuzzedRequest(
                        url,
                        method,
                        body = null,
                        clientId = clientId,
                        clientSecret = clientSecret,
                        consentId = consentId,
                        issues = issues,
                        vector = "header:${param.name}",
                        payload = payload,
                        extraHeader = param.name to payload
                    )
                }
            }

        // --- fuzz body JSON ---
        val bodySchema = operation.requestBody?.content?.values?.firstOrNull()?.schema
        if (bodySchema != null) {
            val baseBody = buildSampleJsonFromSchema(bodySchema)
            repeat(requestsPerVector) {
                val payload = payloads.random()
                val fuzzedBody = mutateJson(baseBody.deepCopy(), payload)
                sendFuzzedRequest(
                    url,
                    method,
                    body = fuzzedBody,
                    clientId = clientId,
                    clientSecret = clientSecret,
                    consentId = consentId,
                    issues = issues,
                    vector = "body",
                    payload = payload
                )
            }
        }
    }

    private suspend fun sendFuzzedRequest(
        url: String,
        method: String,
        body: JsonNode?,
        clientId: String,
        clientSecret: String,
        consentId: String,
        issues: MutableList<Issue>,
        vector: String,
        payload: String,
        extraHeader: Pair<String, String>? = null
    ) {
        try {
            // --- Логируем перед запросом ---
            println("=== FUZZ REQUEST ===")
            println("URL: $url")
            println("METHOD: $method")
            println("VECTOR: $vector")
            println("PAYLOAD: $payload")
            extraHeader?.let { println("EXTRA HEADER: ${it.first}=${it.second}") }
            println("BODY: ${body?.toString() ?: "<empty>"}")
            println("===================")

            val resp: HttpResponse = authService.performRequestWithAuth(
                method = HttpMethod.parse(method),
                url = url,
                clientId = clientId,
                clientSecret = clientSecret,
                consentId = consentId,
                issues = issues,
                bodyBlock = {
                    extraHeader?.let { header(it.first, it.second) }
                    body?.let { setBody(it.toString()) }
                }
            )

            // --- server error capture ---
            if (resp.status.value >= 500) {
                val bodyText = runCatching { resp.bodyAsText() }.getOrElse { "" }
                issues.add(
                    Issue(
                        type = "SERVER_ERROR",
                        severity = Severity.CRITICAL,
                        description = "Сервер вернул ${resp.status.value} при фуззинге ($vector).",
                        url = url,
                        method = method,
                        evidence = "Payload: $payload\nResponse body: $bodyText",
                        recommendation = "Проверить обработку ошибок на сервере и защиту от фуззинга."
                    )
                )
            }

            // --- отчет по фуззу ---
            issues.add(
                Issue(
                    "FUZZ_${vector.uppercase()}",
                    if (resp.status.isSuccess()) Severity.LOW else Severity.MEDIUM,
                    "Fuzz payload '$payload' отправлен, статус ${resp.status.value}",
                    url,
                    method,
                    "payload=$payload"
                )
            )

        } catch (e: Exception) {
            issues.add(
                Issue(
                    "FUZZ_EXCEPTION",
                    Severity.HIGH,
                    "Exception during fuzzing",
                    url,
                    method,
                    "${e.message} | payload=$payload"
                )
            )
        }
    }


    private fun generatePayloads(): List<String> {
        val result = mutableListOf<String>()
        for (p in basePayloads) {
            result += p
            result += mutateDeleteFragment(p)
            result += mutateInvertFragment(p)
            result += mutateDuplicateFragment(p)
            result += mutateBinaryBlob(p)
            result += p.reversed()
            result += p.uppercase()
            result += p.lowercase()
        }
        return result.distinct()
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
        return "$input$blobStr"
    }

    private fun appendQuery(url: String, key: String, value: String): String {
        return if (url.contains("?")) "$url&$key=${encodeURLParameter(value)}"
        else "$url?$key=${encodeURLParameter(value)}"
    }

    private fun encodeURLParameter(v: String): String =
        java.net.URLEncoder.encode(v, Charsets.UTF_8)

    private fun buildSampleJsonFromSchema(schema: io.swagger.v3.oas.models.media.Schema<*>): JsonNode {
        val node = mapper.createObjectNode()
        schema.properties?.forEach { (key, prop) ->
            when (prop.type) {
                "string" -> node.put(key, "sample")
                "integer" -> node.put(key, 1)
                "number" -> node.put(key, 1.0)
                "boolean" -> node.put(key, true)
                "object" -> node.set<JsonNode>(key, buildSampleJsonFromSchema(prop))
                else -> node.put(key, "sample")
            }
        }
        return node
    }

    private fun mutateJson(root: JsonNode, payload: String): JsonNode {
        if (!root.isObject) return root
        val obj = root.deepCopy<ObjectNode>()
        val fields = obj.fieldNames().asSequence().toList()
        if (fields.isEmpty()) return obj
        val target = fields.random()
        obj.put(target, payload)
        return obj
    }
}
