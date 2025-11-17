package com.example.apianalyzer.service

data class UserInput(
    val clientId: String,
    val clientSecret: String,
    val specUrl: String,
    val targetUrl: String,
    val requestingBank: String, // добавлено
    val enableFuzzing: Boolean = false,
    val politenessDelayMs: Int = 200,
    val maxConcurrency: Int = 5
)
