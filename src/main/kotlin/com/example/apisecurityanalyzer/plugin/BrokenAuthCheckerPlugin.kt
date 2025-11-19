package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.swagger.v3.oas.models.Operation

class BrokenAuthCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "BrokenAuth"

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        // чистый контекст от ConsentService
        val cleanCtx = consentService.buildRequestContext(
            fullUrl = url,
            method = method,
            operation = operation,
            userInput = userInput,
            bankToken = bankToken,
            consentId = null
        )

        // BrokenAuth атака → удаляем Authorization
        val badCtx = cleanCtx.copy(headers = cleanCtx.headers.toMutableMap())
        badCtx.headers.remove("Authorization")

        val resp = consentService.executeContext(badCtx)

        if (resp != null && resp.status.value in 200..299) {
            issues.add(
                Issue(
                    type = "BROKEN_AUTH",
                    severity = Severity.HIGH,
                    description = "Эндпоинт успешен без Authorization",
                    url = url,
                    method = method
                )
            )
        }
    }
}
