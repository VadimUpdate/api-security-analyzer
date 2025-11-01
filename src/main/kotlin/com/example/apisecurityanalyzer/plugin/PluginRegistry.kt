package com.example.apianalyzer.service

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import com.example.apianalyzer.plugin.CheckerPlugin
import io.swagger.v3.oas.models.Operation

class PluginRegistry {
    private val plugins = mutableListOf<CheckerPlugin>()

    fun register(plugin: CheckerPlugin) {
        plugins += plugin
    }

    suspend fun runAll(url: String, method: String, operation: Operation, issues: MutableList<Issue>) {
        for (plugin in plugins) {
            try {
                plugin.runCheck(url, method, operation, issues)
            } catch (e: Exception) {
                issues += Issue(
                    type = "PLUGIN_ERROR",
                    path = url,
                    method = method,
                    severity = Severity.LOW, // <- исправлено
                    description = "Ошибка плагина ${plugin.name}",
                    evidence = e.message ?: "unknown"
                )
            }
        }
    }
}
