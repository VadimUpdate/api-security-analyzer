package com.example.apianalyzer.controller

import com.example.apianalyzer.service.ApiScanService
import com.example.apianalyzer.model.ScanReport
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api")
class AnalyzerController(private val apiScanService: ApiScanService) {

    data class ScanRequest(
        val specUrl: String,
        val targetUrl: String,
        val maxConcurrency: Int? = 4,
        val politenessDelayMs: Int? = 150,
        val authClientId: String,        // добавляем обязательные поля
        val authClientSecret: String
    )

    @PostMapping("/analyze")
    fun analyze(@RequestBody request: ScanRequest): ScanReport {
        return apiScanService.runScan(
            specUrl = request.specUrl,
            targetUrl = request.targetUrl,
            maxConcurrency = request.maxConcurrency ?: 4,
            politenessDelayMs = request.politenessDelayMs ?: 150,
            authClientId = request.authClientId,
            authClientSecret = request.authClientSecret
        )
    }
}
