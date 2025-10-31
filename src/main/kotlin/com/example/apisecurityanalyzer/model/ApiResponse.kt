package com.example.apianalyzer.model

data class ApiResponse(
    val endpoint: ApiEndpoint,
    val status: Int,
    val body: String
)
