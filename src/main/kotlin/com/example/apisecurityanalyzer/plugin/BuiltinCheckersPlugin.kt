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

    private val checkers: List<CheckerPlugin>
        get() = buildList {
            if (userInput.enableBOLA) add(BOLACheckerPlugin(clientProvider, consentService, userInput, bankToken))
            if (userInput.enableBrokenAuth) add(BrokenAuthCheckerPlugin(clientProvider, consentService, userInput, bankToken))
            if (userInput.enableSpecChecks) add(SpecCheckerPlugin(clientProvider, consentService, userInput, bankToken))
            if (userInput.enableRateLimiting) add(RateLimitingCheckerPlugin(clientProvider, consentService, userInput, bankToken))
            if (userInput.enableMassAssignment) add(MassAssignmentCheckerPlugin(clientProvider, consentService, userInput))
            if (userInput.enableInjection) add(InjectionCheckerPlugin(clientProvider, consentService, userInput))
        }

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

    /**
     * Запуск проверок с учётом флагов пользователя.
     * Если флаг выключен, проверка не выполняется.
     */
    suspend fun runChecksByFlagsIfEnabled(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>,
        userInput: UserInput
    ) {
        checkers.forEach { checker ->
            when (checker) {
                is BOLACheckerPlugin -> if (userInput.enableBOLA) checker.runCheck(url, method, operation, issues)
                is BrokenAuthCheckerPlugin -> if (userInput.enableBrokenAuth) checker.runCheck(url, method, operation, issues)
                is SpecCheckerPlugin -> if (userInput.enableSpecChecks) checker.runCheck(url, method, operation, issues)
                is RateLimitingCheckerPlugin -> if (userInput.enableRateLimiting) checker.runCheck(url, method, operation, issues)
                is MassAssignmentCheckerPlugin -> if (userInput.enableMassAssignment) checker.runCheck(url, method, operation, issues)
                is InjectionCheckerPlugin -> if (userInput.enableInjection) checker.runCheck(url, method, operation, issues)
            }
        }
    }
}
