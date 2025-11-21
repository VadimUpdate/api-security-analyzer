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
    val issues: List<Issue>,                        // Только найденные уязвимости
    val accountIds: List<String> = emptyList(),
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
    val method: String,
    val description: String? = null,
    val issues: List<Issue> = emptyList(),
    val samples: List<RequestSample> = emptyList()
)

enum class Severity {
    LOW, MEDIUM, HIGH, CRITICAL
}

@JsonInclude(JsonInclude.Include.NON_NULL)
data class RequestSample(
    val url: String,
    val requestBody: Any? = null,
    val responseSample: ResponseSample? = null
)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ResponseSample(
    val status: Int,
    val body: Any? = null
)

data class Issue(
    val type: String,
    val severity: Severity = Severity.MEDIUM,
    val description: String,
    val url: String? = null,
    val method: String? = null,
    val evidence: String? = null,
    val recommendation: String? = null
)