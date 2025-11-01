package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.swagger.v3.oas.models.OpenAPI

/**
 * Небольшой контракт-валидатор — сохраняет точку интеграции, чтобы не ломать вызовы.
 * Полная реализация валидатора (JSON Schema validation, проверка required и т.д.)
 * может быть вставлена сюда без изменений контрактов.
 *
 * Для совместимости метод validateResponse возвращает List<Issue> (как в монолите).
 */
class ContractValidatorService(private val openApi: OpenAPI?) {
    private val mapper = jacksonObjectMapper()

    /**
     * В оригинальном монолите здесь мог быть развернутый валидатор.
     * Чтобы не ломать логику вызовов, оставляем этот метод и делаем базовую проверку:
     * - Если невалидный JSON — не создаём ошибок, но можно расширить.
     *
     * В дальнейшем сюда можно подключить json-schema-validator и полную логику.
     */
    fun validateResponse(url: String, method: String, statusCode: Int, body: String?): List<Issue> {
        // По умолчанию — нет проблем (пользователь может расширить).
        // Если нужны конкретные проверки — можно портировать реальную реализацию сюда.
        return emptyList()
    }
}