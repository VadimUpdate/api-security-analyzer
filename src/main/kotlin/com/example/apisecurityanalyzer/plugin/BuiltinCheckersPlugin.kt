package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.service.FuzzerService
import com.example.apianalyzer.service.AuthService
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation
import kotlinx.coroutines.runBlocking

/**
 * Встроенный набор чекеров для API Security Analyzer.
 * Исправлена сигнатура runCheck и вызов фуззера для FuzzerService.
 */
class BuiltinCheckersPlugin(
    private val fuzzer: FuzzerService,
    private val authService: AuthService,
    private val enableFuzzing: Boolean = true
) {

    fun runCheck(
        url: String,
        method: HttpMethod,
        operation: Operation,
        issues: MutableList<Issue>,
        consentId: String? = null,
        bankToken: String? = null,
        enableFuzzingOverride: Boolean = false
    ) {
        // Простейший placeholder для встроенных проверок
        issues.add(
            Issue(
                type = "PLUGIN_CHECK_PLACEHOLDER",
                severity = Severity.LOW,
                description = "Проверка эндпоинта $method $url выполнена успешно"
            )
        )

        // Запуск фуззинга, если включен
        val fuzzingEnabled = enableFuzzing || enableFuzzingOverride
        if (fuzzingEnabled && operation.extensions?.get("x-scan-disabled") != true) {
            runBlocking {
                fuzzer.fuzzEndpoint(
                    url = url,
                    method = method,
                    consentId = consentId ?: "",
                    bankToken = bankToken ?: "",
                    issues = issues
                )
            }
        }
    }
}
