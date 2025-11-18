package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.swagger.v3.oas.models.Operation
import kotlin.reflect.full.callSuspend

/**
 * Универсальный реестр плагинов.
 */
class PluginRegistry {

    private val plugins = mutableListOf<Any>()

    fun register(plugin: Any) {
        plugins.add(plugin)
    }

    /**
     * Запуск всех плагинов.
     */
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
                val methodRef = plugin::class.members.find { it.name == "runCheck" } ?: continue

                when (methodRef.parameters.size) {

                    // plugin.runCheck(url, method, operation, issues)
                    5 -> methodRef.callSuspend(plugin, url, method, operation, issues)

                    // plugin.runCheck(url, method, operation, issues, enableFuzzing)
                    6 -> methodRef.callSuspend(plugin, url, method, operation, issues, enableFuzzing)

                    else -> {
                        issues += Issue(
                            type = "PLUGIN_SIGNATURE_ERROR",
                            severity = Severity.LOW,
                            description = "Некорректная сигнатура runCheck у ${plugin.javaClass.simpleName}",
                            url = url,
                            method = method
                        )
                    }
                }

            } catch (e: Exception) {
                issues += Issue(
                    type = "PLUGIN_ERROR",
                    severity = Severity.LOW,
                    description = "Ошибка в ${plugin.javaClass.simpleName}: ${e.message}",
                    url = url,
                    method = method
                )
            }
        }
    }
}
