package com.example.apianalyzer.model

data class AnalyzeRequest(
    val specUrl: String,
    val targetUrl: String,
    val maxConcurrency: Int? = 5,
    val politenessDelayMs: Int? = 100
)
