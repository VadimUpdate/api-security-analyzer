package com.example.apianalyzer.service

data class UserInput(
    val specUrl: String,
    val targetUrl: String,
    val clientId: String,
    val clientSecret: String,
    val requestingBank: String,
    val maxConcurrency: Int = 6,
    val politenessDelayMs: Int = 150,
    val enableFuzzing: Boolean = false
)
