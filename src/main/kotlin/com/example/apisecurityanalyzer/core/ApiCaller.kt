package com.example.apianalyzer.core

import com.example.apianalyzer.model.ApiEndpoint
import com.example.apianalyzer.model.ApiResponse
import org.springframework.http.HttpMethod
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import reactor.core.publisher.Mono
import java.net.URI

@Component
class ApiCaller(private val webClient: WebClient) {

    /**
     * Выполняет HTTP запрос к endpoint (синхронно, использует block()).
     * Если endpoint.path содержит path-параметры в виде {id}, они должны быть уже заменены.
     */
    fun call(endpoint: ApiEndpoint): ApiResponse {
        val url = normalizeUrl(endpoint.baseUrl, endpoint.path)

        return try {
            val responseEntityMono: Mono<org.springframework.http.ResponseEntity<String>> =
                webClient.method(mapMethod(endpoint.method))
                    .uri(URI.create(url))
                    .retrieve()
                    .toEntity(String::class.java)

            val responseEntity = responseEntityMono.block() // блокируем — упрощённый синхронный подход

            if (responseEntity == null) {
                ApiResponse(endpoint, 0, "No response (null entity)")
            } else {
                ApiResponse(endpoint, responseEntity.statusCodeValue, responseEntity.body ?: "")
            }
        } catch (ex: Exception) {
            ApiResponse(endpoint, 0, "Request error: ${ex.message}")
        }
    }

    private fun mapMethod(method: String): HttpMethod = when (method.uppercase()) {
        "GET" -> HttpMethod.GET
        "POST" -> HttpMethod.POST
        "PUT" -> HttpMethod.PUT
        "DELETE" -> HttpMethod.DELETE
        "PATCH" -> HttpMethod.PATCH
        else -> HttpMethod.GET
    }

    private fun normalizeUrl(base: String, path: String): String {
        // ensure exactly one slash between base and path
        return when {
            base.endsWith("/") && path.startsWith("/") -> base.removeSuffix("/") + path
            !base.endsWith("/") && !path.startsWith("/") -> "$base/$path"
            else -> base + path
        }
    }
}
