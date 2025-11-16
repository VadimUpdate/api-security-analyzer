package com.example.apianalyzer.model

data class ValidationIssue(
    val description: String,
    val severity: String,
    val recommendation: String? = null,
    val evidence: Map<String, Any>? = null
)
