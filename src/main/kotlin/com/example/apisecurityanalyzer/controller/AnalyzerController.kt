package com.example.apianalyzer.controller

import com.example.apianalyzer.model.UserInput
import com.example.apianalyzer.dto.ScanReportDto
import com.example.apianalyzer.service.ApiScanService
import org.springframework.web.bind.annotation.*
import kotlinx.coroutines.runBlocking

@RestController
@RequestMapping("/api")
class AnalyzerController(private val apiScanService: ApiScanService) {

    data class ScanRequest(
        val specUrl: String,
        val targetUrl: String,
        val clientId: String,
        val clientSecret: String,
        val requestingBank: String,
        val maxConcurrency: Int? = 5,
        val politenessDelayMs: Int? = 200,

        // Флаги атак
        val enableFuzzing: Boolean = false,
        val enableBOLA: Boolean = true,
        val enableBrokenAuth: Boolean = true,
        val enableSpecChecks: Boolean = true,
        val enableRateLimiting: Boolean = true,
        val enableMassAssignment: Boolean = true,
        val enableInjection: Boolean = true,
        val enableSensitiveFiles: Boolean = true,
        val enablePublicSwagger: Boolean = true
    )

    @PostMapping("/analyze")
    fun analyze(@RequestBody request: ScanRequest): ScanReportDto = runBlocking {
        val userInput = UserInput(
            specUrl = request.specUrl,
            targetUrl = request.targetUrl,
            clientId = request.clientId,
            clientSecret = request.clientSecret,
            requestingBank = request.requestingBank,
            maxConcurrency = request.maxConcurrency ?: 5,
            politenessDelayMs = request.politenessDelayMs ?: 200,
            enableFuzzing = request.enableFuzzing,
            enableBOLA = request.enableBOLA,
            enableBrokenAuth = request.enableBrokenAuth,
            enableSpecChecks = request.enableSpecChecks,
            enableRateLimiting = request.enableRateLimiting,
            enableMassAssignment = request.enableMassAssignment,
            enableInjection = request.enableInjection,
            enableSensitiveFiles = request.enableSensitiveFiles,
            enablePublicSwagger = request.enablePublicSwagger
        )

        val report = apiScanService.runScan(userInput)

        // Маппинг ScanReport в DTO для фронта
        ScanReportDto(
            specUrl = report.specUrl,
            targetUrl = report.targetUrl,
            timestamp = report.timestamp,
            totalEndpoints = report.totalEndpoints,
            summary = report.summary,
            issues = report.issues,
            accountIds = report.accountIds,
            issuesByType = report.issuesByType,
            uniqueEndpoints = report.uniqueEndpoints
        )
    }
}
