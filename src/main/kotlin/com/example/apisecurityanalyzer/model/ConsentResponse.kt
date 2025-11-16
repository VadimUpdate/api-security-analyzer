package com.example.apianalyzer.model

data class ConsentResponse(
    val request_id: String? = null,
    val consent_id: String? = null,
    val status: String? = null,
    val message: String? = null,
    val created_at: String? = null,
    val auto_approved: Boolean? = null
)
