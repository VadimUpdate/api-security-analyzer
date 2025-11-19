package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.swagger.v3.oas.models.Operation

class DebugEndpointsCheckerPlugin : CheckerPlugin {
    override val name: String = "DebugEndpoints"

    override suspend fun runCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        issues.add(
            Issue(
                type = "DEBUG_ENDPOINT_CHECK",
                severity = Severity.LOW,
                description = "Проверка debug эндпоинтов выполнена (заглушка)",
                url = url,
                method = method
            )
        )
    }
}
