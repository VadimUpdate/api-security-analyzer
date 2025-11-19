package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.swagger.v3.oas.models.Operation

class BOLACheckerPlugin(private val client: HttpClient) : CheckerPlugin {

    override val name: String = "BOLA/IDOR"

    override suspend fun runCheck(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        try {
            // GET запрос к эндпоинту без авторизации
            val response: HttpResponse = client.request(url) {
                this.method = HttpMethod.parse(method)
            }

            val code = response.status.value
            val body = response.bodyAsText()

            // Проверка BOLA (Broken Object Level Authorization)
            if (method.equals("GET", true) && Regex("/\\d+").containsMatchIn(url)) {
                issues += Issue(
                    type = "BOLA",
                    severity = Severity.MEDIUM,
                    description = "Возможен BOLA: ресурс доступен по ID без авторизации",
                    url = url,
                    method = method
                )
            }

            // Проверка IDOR (Insecure Direct Object Reference)
            if (method.equals("GET", true) && url.contains("user") && url.contains("id", ignoreCase = true)) {
                issues += Issue(
                    type = "IDOR",
                    severity = Severity.MEDIUM,
                    description = "Возможный IDOR: доступ к чужим объектам",
                    url = url,
                    method = method
                )
            }

        } catch (e: Exception) {
            issues += Issue(
                type = "BOLA_IDOR_ERROR",
                severity = Severity.LOW,
                description = "Ошибка проверки BOLA/IDOR: ${e.message}",
                url = url,
                method = method
            )
        }
    }
}
