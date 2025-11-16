package com.example.apianalyzer.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.client.WebClient
import java.time.Duration

@Configuration
class   WebClientConfig {

    @Bean
    fun webClient(): WebClient {
        return WebClient.builder()
            .build()
    }
}
