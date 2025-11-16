package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.ScanReport
import io.ktor.client.statement.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject

/**
 * Безопасное получение текста из HttpResponse
 */
suspend fun safeBodyText(response: HttpResponse): String {
    return try {
        response.bodyAsText()
    } catch (_: Exception) {
        "<unreadable body>"
    }
}

/**
 * Генерация примера JSON по схеме (stub, всегда возвращает пустой объект)
 */
fun buildSampleJsonFromSchema(schema: Any?): JsonObject {
    // Можно расширить для генерации по реальной OpenAPI схеме
    return buildJsonObject { }
}

/**
 * Генерация payload-ов для фуззинга (stub, возвращает базовый список)
 */
fun generateFuzzPayloads(): List<String> {
    return listOf(
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../etc/passwd"
    )
}

/**
 * Добавление Issue в список, если такого ещё нет
 */
fun addIfNotDuplicate(list: MutableList<Issue>, issue: Issue) {
    if (list.none { it.type == issue.type && it.path == issue.path && it.method == issue.method }) {
        list += issue
    }
}

/**
 * JSON форматтер для сериализации/десериализации
 */
val jsonFormatter = Json { prettyPrint = true; encodeDefaults = true }
