package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import com.example.apianalyzer.service.FuzzerService
import io.swagger.v3.oas.models.Operation

class BuiltinCheckersPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val fuzzerService: FuzzerService,
    private val userInput: UserInput,
    private val bankToken: String,
    private val consentId: String
) : CheckerPlugin {

    override val name: String = "BuiltinCheckers"

    private val checkers: List<CheckerPlugin>
        get() = buildList {
            if (userInput.enableBOLA) add(
                BOLACheckerPlugin(
                    clientProvider,
                    consentService,
                    fuzzerService,
                    userInput,
                    bankToken,
                    consentId
                )
            )
            if (userInput.enableBrokenAuth) add(
                BrokenAuthCheckerPlugin(
                    clientProvider,
                    consentService,
                    userInput,
                    bankToken
                )
            )
            if (userInput.enableSpecChecks) add(
                SpecCheckerPlugin(
                    clientProvider,
                    consentService,
                    userInput,
                    bankToken
                )
            )
            if (userInput.enableRateLimiting) add(
                RateLimitingCheckerPlugin(
                    clientProvider,
                    consentService,
                    userInput,
                    bankToken
                )
            )
            if (userInput.enableMassAssignment) add(
                MassAssignmentCheckerPlugin(
                    clientProvider,
                    consentService,
                    userInput,
                    bankToken
                )
            )
            if (userInput.enableInjection) add(
                InjectionCheckerPlugin(
                    clientProvider,
                    consentService,
                    userInput
                )
            )
            if (userInput.enableSensitiveFiles) add(
                SensitiveFilesCheckerPlugin(
                    clientProvider,
                    consentService,
                    userInput,
                    bankToken
                )
            )
        }

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    ) {
        // Если все флаги отключены, пропускаем выполнение
        if (checkers.isEmpty()) return

        for (checker in checkers) {
            checker.runCheck(url, method, operation, issues)
        }
    }
}
