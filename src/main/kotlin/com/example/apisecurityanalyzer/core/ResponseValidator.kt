package com.example.apianalyzer.core

import com.example.apianalyzer.model.ApiResponse
import com.example.apianalyzer.model.ValidationIssue
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.networknt.schema.JsonSchema
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion
import com.networknt.schema.ValidationMessage
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.Operation
import io.swagger.v3.oas.models.responses.ApiResponse as OasApiResponse
import org.springframework.stereotype.Component
import java.util.*

@Component
class ResponseValidator(
    private val objectMapper: ObjectMapper
) {

    private val schemaFactory: JsonSchemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7)

    /**
     * Валидирует ApiResponse в контексте OpenAPI operation (соответствующий Operation).
     * Возвращает список ValidationIssue (пуста если проблем нет).
     */
    fun validate(openAPI: OpenAPI, operation: Operation, oasPathKey: String, resp: ApiResponse): List<ValidationIssue> {
        val issues = mutableListOf<ValidationIssue>()

        // Найдём ApiResponse описание для кода
        val oasResponse = findOasResponseForStatus(operation, resp.status)

        if (oasResponse == null) {
            // если спецификация вообще не описывает этот статус ответа
            issues.add(
                ValidationIssue(
                    description = "Undocumented response status: ${resp.status}",
                    severity = "MEDIUM"
                )
            )
            return issues
        }

        // Есть ли content application/json и схема?
        val content = oasResponse.content
        val mediaType = content?.get("application/json")
        if (mediaType == null) {
            // Если схема не JSON, но у нас есть тело — пометим как LOW, если тело есть
            if (resp.body.isNotBlank()) {
                issues.add(ValidationIssue("Response body present but spec does not define application/json content", "LOW"))
            }
            return issues
        }

        val schemaObj = mediaType.schema
        if (schemaObj == null) {
            // Спецификация описывает application/json, но без schema
            return issues
        }

        // Преобразуем OpenAPI Schema object в JSON-node (упрощённо — подходит для большинства случаев)
        val schemaNode: JsonNode = objectMapper.valueToTree(schemaObj)

        // networknt ожидает полноценную JSON Schema. Если в schemaNode есть "$ref", networknt не развернёт его автоматически.
        // Для MVP — мы валидируем простые inline схемы. Для production нужно развернуть $ref во всем документе.
        try {
            val jsonSchema: JsonSchema = schemaFactory.getSchema(schemaNode)

            val instance: JsonNode? = safeParseJson(resp.body)
            if (instance == null) {
                issues.add(ValidationIssue("Expected JSON body according to spec but response body is empty or not JSON", "HIGH"))
                return issues
            }

            val errors: Set<ValidationMessage> = jsonSchema.validate(instance)
            if (errors.isNotEmpty()) {
                // Преобразуем ошибки в более читабельный вид
                val msg = errors.joinToString("; ") { it.message }
                val severity = determineSeverity(errors)
                issues.add(ValidationIssue("Schema validation failed: $msg", severity.name))
            }
        } catch (ex: Exception) {
            issues.add(ValidationIssue("Schema validation error: ${ex.message}", "MEDIUM"))
        }

        return issues
    }

    private fun findOasResponseForStatus(operation: Operation, status: Int): OasApiResponse? {
        if (operation.responses == null) return null
        val statusStr = status.toString()
        if (operation.responses.containsKey(statusStr)) return operation.responses[statusStr]
        // fallback common success codes
        if (status in 200..299) {
            if (operation.responses.containsKey("200")) return operation.responses["200"]
            if (operation.responses.containsKey("201")) return operation.responses["201"]
        }
        return operation.responses["default"]
    }

    private fun safeParseJson(body: String): JsonNode? {
        if (body.isBlank()) return null
        return try {
            objectMapper.readTree(body)
        } catch (e: Exception) {
            null
        }
    }

    private fun determineSeverity(errors: Set<ValidationMessage>): Severity {
        // простая эвристика: если есть required -> HIGH, иначе MEDIUM
        val required = errors.any { it.message.contains("required", ignoreCase = true) }
        return if (required) Severity.HIGH else Severity.MEDIUM
    }

    private enum class Severity { HIGH, MEDIUM, LOW }
}
