package com.example.apianalyzer.model

data class Issue(
    val type: String,
    val path: String,
    val method: String,
    val severity: String,
    val description: String,
    val evidence: String
)
