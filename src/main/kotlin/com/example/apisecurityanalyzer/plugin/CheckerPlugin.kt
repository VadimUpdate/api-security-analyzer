package com.example.apianalyzer.plugin

import com.example.apianalyzer.model.Issue
import io.swagger.v3.oas.models.Operation

interface CheckerPlugin {
    val name: String
    suspend fun runCheck(
        url: String,
        method: String,
        operation: Operation,
        issues: MutableList<Issue>
    )
}
