package com.example.apianalyzer.model

data class UserInput(
    val clientId: String,
    val clientSecret: String,
    val specUrl: String,
    val targetUrl: String,
    val enableFuzzing: Boolean = false,
    val politenessDelayMs: Int = 200,
    val maxConcurrency: Int = 5
)
