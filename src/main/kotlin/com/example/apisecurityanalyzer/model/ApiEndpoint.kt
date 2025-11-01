package com.example.apianalyzer.model

data class ApiEndpoint(
    val path: String,
    val method: String,
    val summary: String = "",
    val responses: List<String> = emptyList(),
    val baseUrl: String
)
