package com.example.apianalyzer.controller

import com.example.apianalyzer.model.ScanReport
import com.example.apianalyzer.service.ApiScanService
import com.example.apianalyzer.service.UserInput
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
        val maxConcurrency: Int? = 4,
        val politenessDelayMs: Int? = 150,
        val enableFuzzing: Boolean = false
    )

    @PostMapping("/analyze")
    fun analyze(@RequestBody request: ScanRequest): ScanReport = runBlocking {
        val userInput = UserInput(
            specUrl = request.specUrl,
            targetUrl = request.targetUrl,
            clientId = request.clientId,
            clientSecret = request.clientSecret,
            requestingBank = request.requestingBank,
            maxConcurrency = request.maxConcurrency ?: 4,
            politenessDelayMs = request.politenessDelayMs ?: 150,
            enableFuzzing = request.enableFuzzing
        )

        apiScanService.runScan(userInput)
    }
}
