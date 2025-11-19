package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.swagger.v3.oas.models.Operation

class BuiltinCheckersPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "BuiltinCheckers"

    private val checkers: List<CheckerPlugin> = listOf(
        BOLACheckerPlugin(clientProvider, consentService, userInput, bankToken),
        BrokenAuthCheckerPlugin(clientProvider, consentService, userInput, bankToken),
        SpecCheckerPlugin(clientProvider, consentService, userInput, bankToken),
        RateLimitingCheckerPlugin(clientProvider, consentService, userInput, bankToken)
        // при желании можно добавить MassAssignment и другие плагины
    )

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        for (checker in checkers) {
            checker.runCheck(url, method, operation, issues)
        }
    }
}
