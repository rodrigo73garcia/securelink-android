package com.securelink.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.securelink.core.KotlinUrlAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

class BlocklistUpdateWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "BlocklistUpdateWorker"
        private const val BLOCKLIST_URL = "https://raw.githubusercontent.com/rodrigo73garcia/securelink-android/master/blocklists/domains.txt"
    }

    override suspend fun doWork(): Result {
        Log.d(TAG, "Iniciando atualização de blocklist")
        return try {
            withContext(Dispatchers.IO) {
                val domains = downloadBlocklistDomains()
                if (domains != null && domains.isNotEmpty()) {
                    KotlinUrlAnalyzer.loadBlocklist(domains)
                    // Salva localmente para próxima inicialização
                    val file = applicationContext.filesDir.resolve("blocklist.txt")
                    file.writeText(domains.joinToString("\n"))
                    Log.d(TAG, "Blocklist atualizada: ${domains.size} domínios")
                    Result.success()
                } else {
                    Log.w(TAG, "Blocklist vazia ou falha no download")
                    Result.success() // Não retenta - próxima execução agendada vai tentar de novo
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Erro na atualização de blocklist", e)
            Result.success()
        }
    }

    private fun downloadBlocklistDomains(): Set<String>? {
        return try {
            val conn = URL(BLOCKLIST_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = 30000
            conn.readTimeout = 60000
            val text = conn.inputStream.bufferedReader().readText()
            conn.disconnect()
            text.lines()
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith("!") }
                .toSet()
        } catch (e: Exception) {
            Log.w(TAG, "Falha ao baixar blocklist: ${e.message}")
            null
        }
    }
}
