package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.swagger.v3.oas.models.PathItem
import io.swagger.v3.oas.models.parameters.Parameter
import io.swagger.v3.oas.models.media.Schema
import kotlin.random.Random
import kotlinx.coroutines.runBlocking

private val mapper = jacksonObjectMapper()

/** Добавляет issue, если такого ещё нет (тип+путь+метод) */
fun addIfNotDuplicate(issues: MutableList<Issue>, i: Issue) {
    if (issues.none { it.type == i.type && it.path == i.path && it.method == i.method }) issues += i
}

fun addNetworkIssue(issues: MutableList<Issue>, url: String, method: String, title: String, details: String) {
    addIfNotDuplicate(issues, Issue(
        type = "NETWORK_ERROR",
        severity = Severity.HIGH,
        description = title,
        path = url,
        method = method,
        evidence = details
    ))
}

fun extractOperations(pathItem: PathItem): Map<String, io.swagger.v3.oas.models.Operation?> = mapOf(
    "GET" to pathItem.get,
    "POST" to pathItem.post,
    "PUT" to pathItem.put,
    "DELETE" to pathItem.delete,
    "PATCH" to pathItem.patch,
    "HEAD" to pathItem.head,
    "OPTIONS" to pathItem.options
)

fun buildUrlFromPath(base: String, template: String, params: List<Parameter>): String {
    var u = template
    params.filter { it.`in` == "path" }.forEach { u = u.replace("{${it.name}}", Random.nextInt(1, 99).toString()) }
    return base.trimEnd('/') + u
}

fun containsSensitiveField(body: String?): Boolean {
    if (body.isNullOrBlank()) return false
    val keywords = listOf("password", "secret", "token", "apiKey", "ssn")
    return keywords.any { body.contains(it, ignoreCase = true) }
}

fun checkIDOR(url: String, method: String, issues: MutableList<Issue>, clientId: String = "", clientSecret: String = "") {
    if (url.matches(Regex(".*/\\d+"))) {
        addIfNotDuplicate(issues, Issue(
            type = "IDOR",
            severity = Severity.HIGH,
            description = "Возможный IDOR через числовой ID в URL",
            path = url,
            method = method,
            evidence = "Проверьте изменение ID"
        ))
    }
}

/** Быстрая проверка открытого доступа без токена */
fun checkBrokenAuth(client: HttpClient, url: String, method: String, issues: MutableList<Issue>) {
    runBlocking {
        try {
            val resp = client.request(url) { this.method = io.ktor.http.HttpMethod.Get }
            if (resp.status.value in 200..299) {
                addIfNotDuplicate(issues, Issue(
                    type = "BROKEN_AUTH",
                    severity = Severity.HIGH,
                    description = "Эндпоинт доступен без токена",
                    path = url,
                    method = method,
                    evidence = "HTTP ${resp.status.value}"
                ))
            }
        } catch (_: Exception) {}
    }
}

/** Проверка доступности целевого сервера */
suspend fun checkTargetReachable(client: HttpClient, targetUrl: String, paths: Set<String>, issues: MutableList<Issue>): Boolean {
    return try {
        val resp = client.get(targetUrl)
        if (resp.status.value !in 200..399) {
            addNetworkIssue(issues, targetUrl, "GET", "Целевой сервер недоступен", "HTTP ${resp.status.value}")
            false
        } else true
    } catch (e: Exception) {
        addNetworkIssue(issues, targetUrl, "GET", "Целевой сервер недоступен", e.message ?: "unknown")
        false
    }
}

/** Безопасное чтение тела ответа */
fun safeBodyText(resp: HttpResponse): String = runBlocking {
    try { resp.bodyAsText() } catch (_: Exception) { "" }
}

/** Генерация JSON примеров из схемы */
fun buildSampleJsonFromSchema(schema: Schema<*>): List<String> {
    val obj = mutableMapOf<String, Any?>()
    schema.properties?.forEach { (k, v) ->
        obj[k] = when (v.type) {
            "string" -> "string_sample"
            "integer" -> 1
            "number" -> 1.0
            "boolean" -> true
            else -> null
        }
    }
    return listOf(mapper.writeValueAsString(obj))
}

/** Fuzz-пейлоады для инъекций */
fun generateFuzzPayloads(): Sequence<String> = sequence {
    yield("{\"fuzz\":\"' OR '1'='1\"}")
    yield("{\"fuzz\":\"<script>alert(1)</script>\"}")
    yield("{\"fuzz\":\"../../etc/passwd\"}")
}

/** Глобальные проверки публичного доступа к Swagger/OpenAPI */
suspend fun runGlobalChecks(client: HttpClient, targetUrl: String, issues: MutableList<Issue>) {
    val urls = listOf("/swagger-ui.html", "/swagger.json", "/openapi.json")
    for (u in urls) {
        try {
            val resp = client.get(targetUrl.trimEnd('/') + u)
            if (resp.status.value in 200..299) {
                addIfNotDuplicate(issues, Issue(
                    type = "PUBLIC_API_DOCS",
                    severity = Severity.MEDIUM,
                    description = "Swagger/OpenAPI доступен публично",
                    path = targetUrl + u,
                    method = "GET",
                    evidence = "HTTP ${resp.status.value}"
                ))
            }
        } catch (_: Exception) {}
    }
}
