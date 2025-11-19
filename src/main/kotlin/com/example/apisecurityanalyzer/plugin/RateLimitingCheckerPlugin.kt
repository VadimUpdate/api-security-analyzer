package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.service.ClientProvider
import io.ktor.client.request.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class RateLimitingCheckerPlugin(
    private val clientProvider: ClientProvider
) : CheckerPlugin {

    override val name: String = "RateLimiting"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        try {
            repeat(5) {
                clientProvider.client.request(url) {
                    this.method = HttpMethod.parse(method)
                }
            }
        } catch (e: Exception) {
            issues += Issue(
                type = "RATE_LIMITING",
                severity = Severity.MEDIUM,
                description = "Potential rate limiting issue detected: ${e.message}",
                url = url,
                method = method
            )
        }
    }
}
