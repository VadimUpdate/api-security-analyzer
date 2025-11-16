package com.example.apianalyzer.model

import com.fasterxml.jackson.annotation.JsonInclude

@JsonInclude(JsonInclude.Include.NON_NULL)
data class Issue(
    val type: String,
    val severity: Severity = Severity.MEDIUM,
    val description: String,
    val path: String? = null,
    val method: String? = null,
    val evidence: String? = null
)
