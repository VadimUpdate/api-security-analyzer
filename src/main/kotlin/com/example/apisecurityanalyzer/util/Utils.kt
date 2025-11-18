package com.example.apianalyzer.util

import com.example.apianalyzer.model.Issue
import com.example.apianalyzer.model.Severity
import io.ktor.client.statement.*

suspend fun safeBodyText(response: HttpResponse): String {
    return try {
        response.bodyAsText()
    } catch (_: Exception) {
        "<unreadable body>"
    }
}

fun addIfNotDuplicate(list: MutableList<Issue>, issue: Issue) {
    if (list.none { it.type == issue.type && it.url == issue.url && it.method == issue.method }) {
        list += issue
    }
}

fun generateFuzzPayloads(): List<String> {
    return listOf(
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../etc/passwd"
    )
}
