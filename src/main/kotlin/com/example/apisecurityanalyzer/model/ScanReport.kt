package com.example.apianalyzer.model

data class ScanReport(
    val specUrl: String,
    val targetUrl: String,
    val totalEndpoints: Int,
    val issues: List<Issue>,
    val timestamp: String
)
