package com.example.apianalyzer.model

data class UserInput(
    val clientId: String,
    val clientSecret: String,
    val specUrl: String,
    val targetUrl: String,
    val requestingBank: String,

    val enableFuzzing: Boolean = false,

    val enableBOLA: Boolean = true,
    val enableBrokenAuth: Boolean = true,
    val enableSpecChecks: Boolean = true,
    val enableRateLimiting: Boolean = true,
    val enableMassAssignment: Boolean = true,
    val enableInjection: Boolean = true,
    val enableSensitiveFiles: Boolean = true,
    val enablePublicSwagger: Boolean = true,

    val politenessDelayMs: Int = 200,
    val maxConcurrency: Int = 5,

    // новый флаг для ГОСТ
    val useGostGateway: Boolean = false
)
