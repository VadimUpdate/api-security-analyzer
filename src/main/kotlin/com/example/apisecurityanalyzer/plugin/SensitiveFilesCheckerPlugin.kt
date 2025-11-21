package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.service.ClientProvider
import com.example.apianalyzer.service.ConsentService
import io.ktor.client.statement.*
import io.ktor.client.request.*

class SensitiveFilesCheckerPlugin(
    private val clientProvider: ClientProvider,
    private val consentService: ConsentService,
    private val userInput: UserInput,
    private val bankToken: String
) : CheckerPlugin {

    override val name: String = "SensitiveFiles"

    private val sensitivePaths = listOf(
        "/.env",
        "/config.json",
        "/credentials.json",
        "/.git/config",
        "/.htaccess",
        "/.bash_history"
    )

    override suspend fun runCheck(
        url: String,
        method: String,
        operation: io.swagger.v3.oas.models.Operation,
        issues: MutableList<Issue>
    ) {
        for (path in sensitivePaths) {
            val fullUrl = userInput.targetUrl.trimEnd('/') + path

            val response: HttpResponse? = try {
                clientProvider.client.get(fullUrl)
            } catch (_: Exception) {
                null
            }

            response?.let {
                if (it.status.value in 200..299) {
                    issues.add(
                        Issue(
                            type = "SENSITIVE_FILES",
                            severity = Severity.HIGH,
                            description = "Обнаружен доступный чувствительный файл: $path",
                            url = fullUrl,
                            method = "GET"
                        )
                    )
                }
            }
        }
    }
}
