package com.example.apianalyzer.dto

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Summary
import java.time.Instant

data class ScanReportDto(
    val specUrl: String,
    val targetUrl: String,
    val timestamp: Instant,
    val totalEndpoints: Int,
    val summary: Summary,
    val issues: List<Issue>,
    val accountIds: List<String> = emptyList(),
    val issuesByType: Map<String, Int> = emptyMap(),
    val uniqueEndpoints: Int = 0
)
