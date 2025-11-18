package com.example.apianalyzer.service

import com.example.apianalyzer.model.UserInput
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*

class CardService(
    val client: HttpClient
) {
    private val mapper = jacksonObjectMapper()

    suspend fun handleCardPaths(
        pathTemplate: String,
        userInput: UserInput,
        combinedParams: List<io.swagger.v3.oas.models.parameters.Parameter>,
        accountNumber: String? = null,
        cardId: String? = null,
        accountConsentId: String? = null,
        bankToken: String? = null
    ): String {
        val base = userInput.targetUrl
        return when {
            pathTemplate == "/cards" -> {
                if (accountNumber.isNullOrBlank() || accountConsentId.isNullOrBlank() || bankToken.isNullOrBlank()) {
                    "$base/cards?client_id=${userInput.clientId}-1"
                } else {
                    val existingCardId = try {
                        val resp = client.get("$base/cards?client_id=${userInput.clientId}-1&account_id=$accountNumber") {
                            header("Authorization", "Bearer $bankToken")
                            header("X-Consent-Id", accountConsentId)
                            header("X-Requesting-Bank", userInput.clientId)
                            header("Accept", "application/json")
                        }
                        if (resp.status.value != 200) null
                        else mapper.readTree(resp.bodyAsText()).path("data").path("cards").firstOrNull()?.path("cardId")?.asText()
                    } catch (_: Exception) { null }

                    if (!existingCardId.isNullOrBlank()) buildUrlFromPath(base, pathTemplate, combinedParams)
                    else {
                        issueNewCard(base, bankToken, accountConsentId, userInput.clientId, userInput.clientId, accountNumber)
                        buildUrlFromPath(base, pathTemplate, combinedParams)
                    }
                }
            }
            pathTemplate.contains("{card_id}") -> {
                val realCardId = cardId ?: "card-sample-id"
                buildUrlFromPath(base, pathTemplate.replace("{card_id}", realCardId), combinedParams)
            }
            else -> buildUrlFromPath(base, pathTemplate, combinedParams)
        }
    }

    private suspend fun issueNewCard(
        bankBaseUrl: String,
        bankToken: String?,
        consentId: String?,
        requestingBank: String,
        clientId: String,
        accountNumber: String?,
        cardName: String = "Visa Classic",
        cardType: String = "debit"
    ): String? {
        if (accountNumber.isNullOrBlank() || bankToken.isNullOrBlank() || consentId.isNullOrBlank()) return null

        val url = "$bankBaseUrl/cards?client_id=$clientId-1"
        return try {
            val resp = client.post(url) {
                contentType(ContentType.Application.Json)
                header("Authorization", "Bearer $bankToken")
                header("X-Requesting-Bank", requestingBank)
                header("X-Consent-Id", consentId)
                setBody(
                    mapOf(
                        "account_number" to accountNumber,
                        "card_name" to cardName,
                        "card_type" to cardType
                    )
                )
            }
            mapper.readTree(resp.bodyAsText()).path("cardId").asText(null)
        } catch (_: Exception) { null }
    }

    suspend fun getFirstAccount(bankBaseUrl: String, bankToken: String, consentId: String, clientId: String): String? {
        val url = "$bankBaseUrl/accounts?client_id=${clientId}-1"
        return try {
            val response = client.get(url) {
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", clientId)
                header("Accept", "application/json")
            }
            mapper.readTree(response.bodyAsText()).path("data").path("account").firstOrNull()?.path("accountId")?.asText()
        } catch (_: Exception) { null }
    }

    suspend fun getFirstAccountNumber(bankBaseUrl: String, bankToken: String, consentId: String, clientId: String, accountId: String): String? {
        val url = "$bankBaseUrl/accounts?client_id=${clientId}-1"
        return try {
            val response = client.get(url) {
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", clientId)
                header("Accept", "application/json")
            }
            mapper.readTree(response.bodyAsText()).path("data").path("account").firstOrNull()?.path("accountNumber")?.asText()
        } catch (_: Exception) { null }
    }

    suspend fun getFirstCard(bankBaseUrl: String, bankToken: String, consentId: String, clientId: String, accountNumber: String?): String? {
        if (accountNumber.isNullOrBlank()) return null
        val getUrl = "$bankBaseUrl/cards?client_id=${clientId}-1&account_id=$accountNumber"
        return try {
            val resp = client.get(getUrl) {
                header("Authorization", "Bearer $bankToken")
                header("X-Consent-Id", consentId)
                header("X-Requesting-Bank", clientId)
                header("Accept", "application/json")
            }
            mapper.readTree(resp.bodyAsText()).path("data").path("cards").firstOrNull()?.path("cardId")?.asText()
        } catch (_: Exception) { null }
    }

    private fun buildUrlFromPath(
        baseUrl: String,
        pathTemplate: String,
        params: List<io.swagger.v3.oas.models.parameters.Parameter>
    ): String {
        return "$baseUrl$pathTemplate"
    }
}
