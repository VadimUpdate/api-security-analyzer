package com.example.apianalyzer.core

import com.example.apianalyzer.model.ApiEndpoint
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.parser.OpenAPIV3Parser
import io.swagger.v3.parser.core.models.ParseOptions
import io.swagger.v3.parser.core.models.SwaggerParseResult
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import java.time.Duration

@Component
class OpenApiParser(
    private val webClient: WebClient
) {

    private val log = LoggerFactory.getLogger(OpenApiParser::class.java)

    fun parse(specUrl: String, baseUrl: String): List<ApiEndpoint> {

        // 1) Скачиваем спецификацию
        val rawSpec = webClient.get().uri(specUrl)
            .retrieve()
            .bodyToMono(String::class.java)
            .block()
            ?: throw IllegalArgumentException("Cannot download spec: $specUrl")

        // 2) Downgrade 3.1 -> 3.0.3 (SwaggerParser requirement)
        val fixedSpec = rawSpec
            .replace("\"openapi\":\"3.1.0\"", "\"openapi\":\"3.0.3\"")
            .replace("'openapi':'3.1.0'", "'openapi':'3.0.3'")

        // 3) ParseOptions
        val options = ParseOptions().apply {
            isResolve = true
            isResolveFully = false
        }

        val result = OpenAPIV3Parser().readContents(fixedSpec, null, options)

        result.messages?.forEach { log.warn("Parser message: $it") }

        val openAPI = result.openAPI
            ?: throw IllegalArgumentException("parser returned null openAPI (even after downgrade)")

        // 4) Extract endpoints
        val endpoints = mutableListOf<ApiEndpoint>()

        openAPI.paths?.forEach { (path, item) ->
            item.readOperationsMap().forEach { (method, op) ->
                endpoints.add(
                    ApiEndpoint(
                        path = path,
                        method = method.name,
                        summary = op.summary ?: "",
                        responses = op.responses?.keys?.toList() ?: emptyList(),
                        baseUrl = baseUrl
                    )
                )
            }
        }

        return endpoints
    }
}
