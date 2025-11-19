package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class SpecCheckerPlugin(private val client: HttpClient) : CheckerPlugin {

    override val name: String = "Spec"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        try {
            val response: HttpResponse = client.request(url) {
                this.method = HttpMethod.parse(method)
            }
            if (response.status.value >= 400) {
                issues += Issue(
                    type = "SPEC_MISMATCH",
                    severity = Severity.MEDIUM,
                    description = "Ответ не соответствует спецификации (HTTP ${response.status.value})",
                    url = url,
                    method = method
                )
            }
        } catch (e: Exception) {
            issues += Issue(
                type = "SPEC_CHECK_PLUGIN_ERROR",
                severity = Severity.LOW,
                description = "Ошибка SpecChecker: ${e.message}",
                url = url,
                method = method
            )
        }
    }
}
