package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.client.plugins.*
import io.ktor.http.*
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.media.StringSchema
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class AuthService(private val clientProvider: ClientProvider) {
    private val mapper = jacksonObjectMapper()
    private val client: HttpClient get() = clientProvider.client

    @Volatile
    var authToken: String? = null
    private val tokenMutex = Mutex()

    suspend fun performRequestWithAuth(
        method: HttpMethod,
        url: String,
        clientId: String,
        clientSecret: String,
        openApi: OpenAPI?,
        bodyBlock: (HttpRequestBuilder.() -> Unit)? = null,
        issues: MutableList<Issue>
    ): HttpResponse {
        suspend fun doRequest(token: String?): HttpResponse {
            return client.request(url) {
                this.method = method
                token?.let { header("Authorization", "Bearer $it") }
                bodyBlock?.invoke(this)
            }
        }

        val cur = authToken
        try {
            return doRequest(cur)
        } catch (e: ResponseException) {
            val status = try { e.response.status.value } catch (_: Exception) { null }
            if (status == 401) {
                tokenMutex.withLock {
                    val newToken = obtainBearerToken(openApi, url, clientId, clientSecret, issues)
                    if (!newToken.isNullOrBlank()) authToken = newToken
                }
                return doRequest(authToken)
            } else throw e
        }
    }

    suspend fun obtainBearerToken(
        openApi: OpenAPI?,
        baseUrlCandidate: String,
        fallbackClientId: String,
        fallbackClientSecret: String,
        issues: MutableList<Issue>
    ): String? {
        try {
            // ищем POST path с application/x-www-form-urlencoded
            val tokenPath = openApi?.paths?.entries?.find { (path, item) ->
                item.post?.requestBody?.content?.keys?.any {
                    it.contains("application/x-www-form-urlencoded", ignoreCase = true)
                } == true
            }?.key ?: "/oauth/token" // fallback

            val tokenUrl = baseUrlCandidate.trimEnd('/') + tokenPath

            // параметры из OpenAPI, если указаны
            val formParams = Parameters.build {
                val reqBody = openApi?.paths?.get(tokenPath)?.post?.requestBody
                val schemaProps = reqBody?.content
                    ?.get("application/x-www-form-urlencoded")
                    ?.schema?.properties ?: emptyMap<String, io.swagger.v3.oas.models.media.Schema<*>>()

                append(
                    "grant_type",
                    (schemaProps["grant_type"] as? StringSchema)?.default ?: "client_credentials"
                )
                append(
                    "client_id",
                    (schemaProps["client_id"] as? StringSchema)?.default ?: fallbackClientId
                )
                append(
                    "client_secret",
                    (schemaProps["client_secret"] as? StringSchema)?.default ?: fallbackClientSecret
                )
            }

            val resp: HttpResponse = client.submitForm(
                url = tokenUrl,
                formParameters = formParams,
                encodeInQuery = false
            )

            val body = resp.bodyAsText()
            return mapper.readTree(body).get("access_token")?.asText()

        } catch (e: Exception) {
            issues.add(
                Issue(
                    type = "TOKEN_ERROR",
                    path = baseUrlCandidate,
                    method = "POST",
                    severity = Severity.HIGH,
                    description = "Не удалось получить токен",
                    evidence = e.message ?: "unknown"
                )
            )
            return null
        }
    }
}
