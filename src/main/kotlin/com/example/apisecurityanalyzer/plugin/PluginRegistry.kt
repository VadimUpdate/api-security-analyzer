package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import io.swagger.v3.oas.models.Operation
import kotlin.reflect.full.callSuspend

/**
 * Универсальный реестр плагинов (без интерфейса CheckerPlugin).
 * Поддерживает регистрацию любых плагинов, у которых есть метод runCheck().
 */
class PluginRegistry {
    private val plugins = mutableListOf<Any>()

    fun register(plugin: Any) {
        plugins.add(plugin)
    }

    @Suppress("UNCHECKED_CAST")
    suspend fun runAll(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>,
        enableFuzzing: Boolean = false
    ) {
        for (plugin in plugins) {
            try {
                val methodRef = plugin::class.members.find { it.name == "runCheck" }
                if (methodRef != null) {
                    if (methodRef.parameters.size == 5) {
                        methodRef.callSuspend(plugin, url, method, operation, issues)
                    } else {
                        // если плагин поддерживает флаг
                        methodRef.callSuspend(plugin, url, method, operation, issues, enableFuzzing)
                    }
                }
            } catch (e: Exception) {
                issues.add(
                    com.example.apianalyzer.model.Issue(
                        type = "PLUGIN_ERROR",
                        severity = com.example.apianalyzer.model.Severity.LOW,
                        description = "Ошибка при выполнении ${plugin.javaClass.simpleName}: ${e.message}",
                        path = url,
                        method = method
                    )
                )
            }
        }
    }
}
