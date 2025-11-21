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
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import org.springframework.stereotype.Service
import kotlin.random.Random
import java.util.Collections

@Service
class FuzzerService(
    private val authService: AuthService
) {

    private val mapper = jacksonObjectMapper()

    private val sqlPayloads = listOf(
        "' OR '1'='1", "\" OR \"1\"=\"1", "' UNION SELECT null --",
        "\" UNION SELECT version() --", "'; DROP TABLE users; --",
        "\"; DROP TABLE accounts; --"
    )

    private val xssPayloads = listOf(
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=confirm(1)>", "<a href=javascript:alert(1)>click</a>"
    )

    private val pathPayloads = listOf(
        "../../../etc/passwd", "/../../../../windows/win.ini",
        "../", "..\\..\\..\\", "/etc/shadow", "/var/log/syslog"
    )

    private val commandPayloads = listOf(
        "test; ls -la", "1; cat /etc/passwd", "`id`", "$(whoami)"
    )

    private val templatePayloads = listOf(
        "{{7*7}}", "{{config}}", "<% 7*7 %>", "${7*7}", "#{7*7}"
    )

    private val unicodePayloads = listOf(
        "АБВГДЕЁЖ", "\u0000\u0001\u0002test", "∞∞∞∞∞", "🔥🔥🔥", "💀 DROP 💀"
    )

    private val basePayloads =
        sqlPayloads + xssPayloads + pathPayloads + commandPayloads + templatePayloads + unicodePayloads

    private val semaphore = Semaphore(5)

    var requestsPerVector: Int = 4
    var politenessDelayMs: Long = 150L

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
        val allIssues = Collections.synchronizedList(mutableListOf<Issue>())

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
        val payloads = generatePayloadsForContext(operation)

        operation.parameters
            ?.filterIsInstance<QueryParameter>()
            ?.forEach { param ->
                repeat(requestsPerVector) {
                    val payload = payloads.random()
                    val fuzzedUrl = appendQuery(url, param.name, payload)
                    sendFuzzedRequest(
                        fuzzedUrl, httpMethod, null,
                        clientId, clientSecret, consentId, issues,
                        "query:${param.name}", payload, null
                    )
                }
            }

        operation.parameters
            ?.filterIsInstance<HeaderParameter>()
            ?.forEach { param ->
                repeat(requestsPerVector) {
                    val payload = payloads.random()
                    sendFuzzedRequest(
                        url, httpMethod, null,
                        clientId, clientSecret, consentId, issues,
                        "header:${param.name}", payload,
                        param.name to payload
                    )
                }
            }

        val bodySchema = operation.requestBody?.content?.values?.firstOrNull()?.schema
        if (bodySchema != null) {
            val baseJson = buildSampleJsonFromSchema(bodySchema)
            repeat(requestsPerVector) {
                val payload = payloads.random()
                val fuzzedBody = mutateJsonAdvanced(baseJson.deepCopy(), payload)
                sendFuzzedRequest(
                    url, httpMethod, fuzzedBody,
                    clientId, clientSecret, consentId, issues,
                    "body", payload, null
                )
            }
        }
    }

    private fun generatePayloadsForContext(operation: Operation): List<String> {
        val ctx = basePayloads.toMutableList()

        operation.parameters?.forEach { p ->
            if (p.schema?.format == "email") {
                ctx += "test@example.com<script>"
            }
            if (p.schema?.type == "integer") {
                ctx += "9999999999"
                ctx += "-1"
                ctx += "0 OR 1=1"
            }
        }

        return generateMutations(ctx).shuffled()
    }

    private fun generateMutations(base: List<String>): List<String> {
        val result = mutableListOf<String>()
        for (p in base) {
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
        val blob = ByteArray(8) { Random.nextInt(0, 255).toByte() }
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
                "array" -> {
                    val arr = mapper.createArrayNode()
                    arr.add("sample")
                    node.set<JsonNode>(k, arr)
                }
                else -> node.put(k, "sample")
            }
        }
        return node
    }

    private fun mutateJsonAdvanced(root: JsonNode, payload: String): JsonNode {
        val obj = root.deepCopy<ObjectNode>()
        obj.fieldNames().forEachRemaining { k ->
            when (Random.nextInt(0, 5)) {
                0 -> obj.put(k, payload)
                1 -> obj.put(k, "${payload}_EXT")
                2 -> obj.put(k, Random.nextInt(0, 99999))
                3 -> obj.put(k, "<$payload>")
                else -> obj.put(k, mutateBinaryBlob(payload))
            }
        }
        obj.put("extra_${Random.nextInt(0, 999)}", payload)
        return obj
    }

    private suspend fun sendFuzzedRequest(
        url: String,
        method: HttpMethod,
        body: JsonNode?,
        clientId: String,
        clientSecret: String,
        consentId: String,
        issues: MutableList<Issue>,
        vector: String,
        payload: String,
        extraHeader: Pair<String, String>?
    ) {
        semaphore.acquire()
        delay(politenessDelayMs)

        try {
            val response = authService.performRequestWithAuth(
                method = method,
                url = url,
                clientId = clientId,
                clientSecret = clientSecret,
                consentId = consentId,
                bodyBlock = {
                    extraHeader?.let { header(it.first, it.second) }
                    body?.let {
                        setBody(mapper.writeValueAsString(it))
                        contentType(ContentType.Application.Json)
                    }
                },
                issues = issues // <- теперь передаем отдельным именованным параметром
            )

            val text = runCatching { response.bodyAsText() }.getOrElse { "" }

            detectAdditionalVulnerabilities(url, method, vector, payload, response, text, issues)

            if (response.status.value >= 500) {
                issues.add(
                    Issue(
                        "SERVER_ERROR",
                        Severity.CRITICAL,
                        "Server returned ${response.status.value} during fuzzing ($vector)",
                        url,
                        method.value,
                        "payload=$payload\nresponse=$text",
                        "Validate server error handling"
                    )
                )
            }

            issues.add(
                Issue(
                    "FUZZ_${vector.uppercase()}",
                    if (response.status.isSuccess()) Severity.LOW else Severity.MEDIUM,
                    "Fuzz payload '$payload' → HTTP ${response.status.value}",
                    url,
                    method.value,
                    "payload=$payload"
                )
            )

        } catch (ex: Exception) {
            val msg = ex.message ?: ""
            if (!msg.contains("token", true)) {
                issues.add(
                    Issue(
                        "FUZZ_EXCEPTION",
                        Severity.HIGH,
                        "Exception during fuzzing: ${ex.message}",
                        url,
                        method.value,
                        "${ex.message} | payload=$payload"
                    )
                )
            }
        } finally {
            semaphore.release()
        }
    }


    private fun detectAdditionalVulnerabilities(
        url: String,
        method: HttpMethod,
        vector: String,
        payload: String,
        response: HttpResponse,
        body: String,
        issues: MutableList<Issue>
    ) {
        if (
            body.contains("SQL", true) ||
            body.contains("syntax error", true) ||
            body.contains("MySQL", true) ||
            body.contains("SQLite", true)
        ) {
            issues.add(
                Issue(
                    "SQL_INJECTION_REFLECTION",
                    Severity.HIGH,
                    "Server returned SQL error",
                    url, method.value,
                    "payload=$payload\nresponse=$body"
                )
            )
        }

        if (
            body.contains("Exception:", true) ||
            body.contains("NullReference", true) ||
            body.contains("Traceback", true)
        ) {
            issues.add(
                Issue(
                    "STACK_TRACE_LEAK",
                    Severity.HIGH,
                    "Stack trace leaked",
                    url, method.value,
                    body
                )
            )
        }

        if (body.contains(payload, true)) {
            issues.add(
                Issue(
                    "XSS_REFLECTION",
                    Severity.HIGH,
                    "Payload reflected",
                    url, method.value,
                    "payload=$payload\nresponse=$body"
                )
            )
        }

        if (
            body.contains("etc/passwd", true) ||
            body.contains("root:", true) ||
            body.contains("No such file", true)
        ) {
            issues.add(
                Issue(
                    "LFI_PATH_INDICATOR",
                    Severity.HIGH,
                    "Possible file traversal",
                    url, method.value,
                    body
                )
            )
        }

        if (
            body.contains("{{") ||
            body.contains("<%") ||
            body.contains("#{")
        ) {
            issues.add(
                Issue(
                    "TEMPLATE_INJECTION_INDICATOR",
                    Severity.HIGH,
                    "Template expression leaked",
                    url, method.value,
                    body
                )
            )
        }
    }

    private fun appendQuery(url: String, key: String, value: String): String {
        val e = java.net.URLEncoder.encode(value, Charsets.UTF_8)
        return if ("?" in url) "$url&$key=$e" else "$url?$key=$e"
    }

    private fun extractMethod(method: String): HttpMethod =
        when (method.uppercase()) {
            "GET" -> HttpMethod.Get
            "POST" -> HttpMethod.Post
            "PUT" -> HttpMethod.Put
            "DELETE" -> HttpMethod.Delete
            "PATCH" -> HttpMethod.Patch
            "OPTIONS" -> HttpMethod.Options
            else -> HttpMethod.Get
        }
}
