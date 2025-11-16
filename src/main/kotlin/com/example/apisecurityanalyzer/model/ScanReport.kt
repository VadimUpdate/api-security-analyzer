package com.example.apianalyzer.model

import com.fasterxml.jackson.annotation.JsonInclude
import java.time.Instant

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ScanReport(
    val specUrl: String,
    val targetUrl: String,
    val timestamp: Instant,
    val totalEndpoints: Int,
    val summary: Summary,
    val issues: List<Issue>,
    val issuesByType: Map<String, Int> = emptyMap(),
    val uniqueEndpoints: Int = 0
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class Summary(
    val totalIssues: Int,
    val issuesByType: Map<String, Int>,
    val uniqueEndpoints: Int
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class Endpoint(
    val path: String,
    val methods: List<EndpointMethod>
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class EndpointMethod(
    val method: String,                   // GET, POST, PUT, PATCH, DELETE
    val description: String? = null,      // описание из OpenAPI
    val issues: List<Issue> = emptyList(),
    val samples: List<RequestSample> = emptyList()
)

enum class Severity {
    LOW, MEDIUM, HIGH, CRITICAL
}

@JsonInclude(JsonInclude.Include.NON_NULL)
data class RequestSample(
    val url: String,
    val requestBody: Any? = null,        // Может быть Map или объект
    val responseSample: ResponseSample? = null
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ResponseSample(
    val status: Int,
    val body: Any? = null
)
