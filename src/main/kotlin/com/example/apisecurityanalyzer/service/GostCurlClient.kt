package com.example.apianalyzer.service

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.security.KeyStore
import java.security.Security
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

object GostHttpClient {

    init {
        // Для CryptoPro CSP на Windows провайдер обычно уже зарегистрирован, если нет — можно подключить:
        // Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider()) // пример для BouncyCastle
        // CryptoPro JCP обычно автоматически добавляется в Windows
    }

    private fun createSSLContext(aliasCN: String): SSLContext {
        // Загружаем сертификаты из Windows-MY
        val ks = KeyStore.getInstance("Windows-MY")
        ks.load(null, null)

        // Находим нужный сертификат по CN
        val alias = ks.aliases().toList().firstOrNull { it.contains(aliasCN) }
            ?: throw IllegalArgumentException("Сертификат с CN=$aliasCN не найден в Windows-MY")

        val kmf = KeyManagerFactory.getInstance("SunX509")
        kmf.init(ks, null) // закрытый ключ уже в MY, пароль не нужен

        val tmf = TrustManagerFactory.getInstance("SunX509")
        tmf.init(ks) // доверяем всем корням из MY

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(kmf.keyManagers, tmf.trustManagers, null)

        return sslContext
    }

    suspend fun get(url: String, aliasCN: String = "Вадим", token: String? = null): String =
        withContext(Dispatchers.IO) {
            val sslContext = createSSLContext(aliasCN)
            val connection = URL(url).openConnection() as HttpsURLConnection
            connection.sslSocketFactory = sslContext.socketFactory
            connection.requestMethod = "GET"
            token?.let { connection.setRequestProperty("Authorization", "Bearer $it") }

            val response = connection.inputStream.bufferedReader().readText()
            connection.disconnect()
            response
        }

    suspend fun postJson(url: String, body: String, aliasCN: String = "Вадим", token: String? = null): String =
        withContext(Dispatchers.IO) {
            val sslContext = createSSLContext(aliasCN)
            val connection = URL(url).openConnection() as HttpsURLConnection
            connection.sslSocketFactory = sslContext.socketFactory
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            token?.let { connection.setRequestProperty("Authorization", "Bearer $it") }

            connection.doOutput = true
            connection.outputStream.bufferedWriter().use { it.write(body) }

            val response = connection.inputStream.bufferedReader().readText()
            connection.disconnect()
            response
        }
}
