package com.example.apianalyzer.core

import com.example.apianalyzer.model.ApiEndpoint
import io.swagger.v3.parser.OpenAPIV3Parser
import io.swagger.v3.oas.models.Operation
import org.springframework.stereotype.Component

@Component
class OpenApiParser {

    fun parse(specPath: String, baseUrl: String): List<ApiEndpoint> {
        val openAPI = OpenAPIV3Parser().read(specPath)
            ?: throw IllegalArgumentException("Не удалось прочитать спецификацию: $specPath")

        val endpoints = mutableListOf<ApiEndpoint>()

        openAPI.paths?.forEach { (path, item) ->
            item.readOperationsMap().forEach { (method, operation) ->
                endpoints.add(
                    ApiEndpoint(
                        path = path,
                        method = method.name,
                        summary = operation.summary ?: "",
                        responses = operation.responses?.keys?.toList() ?: emptyList(),
                        baseUrl = baseUrl // <- теперь доступно
                    )
                )
            }
        }

        return endpoints
    }
}
