package com.example.apianalyzer.service

import com.example.apianalyzer.model.*
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.setBody
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import org.springframework.stereotype.Service

@Service
class ConsentService(private val clientProvider: ClientProvider, private val authService: AuthService) {
    private val client get() = clientProvider.client
    private val mapper = jacksonObjectMapper()

    suspend fun createAccountConsent(userInput: UserInput, bankToken: String, issues: MutableList<Issue>): String? {
        return try { authService.createConsent(userInput.targetUrl, userInput.clientId, userInput.clientSecret, issues) } catch (_: Exception) { null }
    }

    suspend fun createPaymentConsent(userInput: UserInput, bankToken: String, issues: MutableList<Issue>): String? {
        val url = "${userInput.targetUrl}/payment-consents/request"
        return try {
            val response = client.post(url) {
                contentType(ContentType.Application.Json)
                header("Authorization", "Bearer $bankToken")
                header("X-Requesting-Bank", userInput.requestingBank)
                setBody(
                    """
                    {
                      "requesting_bank": "${userInput.requestingBank}",
                      "client_id": "${userInput.clientId}-1",
                      "consent_type": "single_use",
                      "amount": 100.0,
                      "debtor_account": "",
                      "reference": "API scan payment"
                    }
                    """.trimIndent()
                )
            }
            if (response.status.value != 200) return null
            mapper.readTree(response.bodyAsText()).path("consent_id").asText(null)
        } catch (ex: Exception) {
            issues.add(Issue("PAYMENT_CONSENT_FAIL", Severity.HIGH, "Не удалось создать Payment Consent: ${ex.message}"))
            null
        }
    }

    suspend fun createProductAgreementConsent(userInput: UserInput, bankToken: String, issues: MutableList<Issue>): Pair<String?, String?> {
        val url = "${userInput.targetUrl}/product-agreement-consents/request?client_id=${userInput.clientId}-1"
        return try {
            val response = client.post(url) {
                contentType(ContentType.Application.Json)
                header("Authorization", "Bearer $bankToken")
                header("X-Requesting-Bank", userInput.requestingBank)
                setBody(
                    """
                    {
                      "requesting_bank": "${userInput.requestingBank}",
                      "client_id": "${userInput.clientId}-1",
                      "read_product_agreements": true,
                      "open_product_agreements": true,
                      "close_product_agreements": false,
                      "allowed_product_types": ["deposit","card"],
                      "max_amount": 1000000.00,
                      "valid_until": "2025-12-31T23:59:59",
                      "reason": "Финансовый агрегатор для управления продуктами"
                    }
                    """.trimIndent()
                )
            }
            val json = mapper.readTree(response.bodyAsText())
            json.path("consent_id").asText(null) to json.path("request_id").asText(null)
        } catch (ex: Exception) {
            issues.add(Issue("PRODUCT_CONSENT_FAIL", Severity.HIGH, "Не удалось создать Product Agreement Consent: ${ex.message}"))
            null to null
        }
    }

    suspend fun performEnhancedChecks(
        url: String,
        method: String,
        issues: MutableList<Issue>,
        bankToken: String,
        consentId: String,
        userInput: UserInput,
        productRequestId: String? = null
    ) {
        val httpMethod = HttpMethod.parse(method)
        val consentHeaderName = when {
            url.contains("/product-agreements") -> "X-Product-Agreement-Consent-Id"
            url.contains("/cards") -> "X-Consent-Id"
            else -> "X-Consent-Id"
        }

        val response = try {
            client.request(url) {
                this.method = httpMethod
                header("Authorization", "Bearer $bankToken")
                header(consentHeaderName, consentId)
                header("X-Requesting-Bank", if (url.contains("/cards")) userInput.clientId else userInput.requestingBank)
                if (httpMethod != HttpMethod.Get) {
                    contentType(ContentType.Application.Json)
                    setBody("{}")
                }
            }
        } catch (ex: Exception) {
            issues.add(Issue("REQUEST_FAILED", Severity.MEDIUM, "$method $url → Exception: ${ex.message}"))
            return
        }

        val status = response.status.value
        val body = runCatching { response.bodyAsText() }.getOrNull()
        if (status == 403)
            issues.add(Issue("ENDPOINT_FORBIDDEN", Severity.LOW, "$method $url → 403", url, method))

        checkSensitiveFields(body, url, method, issues)
    }

    private fun checkSensitiveFields(body: String?, url: String, method: String, issues: MutableList<Issue>) {
        if (body.isNullOrBlank()) return
        val json = runCatching { mapper.readTree(body) }.getOrNull() ?: return
        val sensitive = listOf("password", "token", "secret", "ssn", "creditCard", "dob")

        fun traverse(node: com.fasterxml.jackson.databind.JsonNode) {
            if (node.isObject) {
                node.fields().forEach { (key, value) ->
                    if (sensitive.any { key.contains(it, ignoreCase = true) }) {
                        issues.add(Issue("EXCESSIVE_DATA_EXPOSURE", Severity.HIGH, "Ответ содержит чувствительное поле: $key", url, method))
                    }
                    traverse(value)
                }
            } else if (node.isArray) node.forEach { traverse(it) }
        }
        traverse(json)
    }

    fun selectConsentForPath(url: String, paymentConsentId: String?, productConsentId: String?, accountConsentId: String?): String? {
        return when {
            url.startsWith("/payment-consents") -> paymentConsentId
            url.startsWith("/product-agreement-consents") -> productConsentId
            url.startsWith("/product-agreements") -> productConsentId
            url.startsWith("/cards") -> accountConsentId
            else -> accountConsentId
        }
    }
}

fun String.removeQueryParam(param: String): String {
    val uri = java.net.URI(this)
    val query = uri.query?.split("&")?.filterNot { it.startsWith("$param=") }?.joinToString("&")
    return java.net.URI(uri.scheme, uri.authority, uri.path, query, uri.fragment).toString()
}
