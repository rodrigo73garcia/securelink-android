package com.securelink.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.securelink.core.SecureLinkEngine
import com.securelink.data.repository.BlocklistRepository
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.Dispatchers
import javax.inject.Inject

@AndroidEntryPoint
class BlocklistUpdateWorker @Inject constructor(
    context: Context,
    params: WorkerParameters,
    private val blocklistRepository: BlocklistRepository
) : CoroutineWorker(context, params) {

    private const val TAG = "BlocklistUpdateWorker"
    private const val BLOCKLIST_URL = "https://raw.githubusercontent.com/usuario/securelink-blocklists/main/blocklist.bloom"
    private const val BLOCKLIST_VERSION_URL = "https://raw.githubusercontent.com/usuario/securelink-blocklists/main/version.json"

    override suspend fun doWork(): Result {
        Log.d(TAG, "Iniciando atualização de blocklist")
        
        return try {
            withContext(Dispatchers.IO) {
                // Verifica se há nova versão
                val currentVersion = blocklistRepository.getBlocklistVersion()
                val latestVersion = fetchLatestVersion()
                
                if (latestVersion != null && latestVersion > currentVersion) {
                    Log.d(TAG, "Nova versão de blocklist disponível: $latestVersion (atual: $currentVersion)")
                    
                    val bloomData = downloadBlocklist()
                    if (bloomData != null) {
                        // Salva no armazenamento interno
                        val file = applicationContext.filesDir.resolve("blocklist.bloom")
                        file.writeBytes(bloomData)
                        
                        // Carrega no engine nativo
                        val success = SecureLinkEngine.loadBloomFilter(file.absolutePath)
                        if (success) {
                            blocklistRepository.setBlocklistVersion(latestVersion)
                            blocklistRepository.setLastUpdateTime(System.currentTimeMillis())
                            Log.d(TAG, "Blocklist atualizada com sucesso para versão $latestVersion")
                            Result.success()
                        } else {
                            Log.e(TAG, "Falha ao carregar bloom filter no engine nativo")
                            Result.retry()
                        }
                    } else {
                        Log.e(TAG, "Falha ao baixar blocklist")
                        Result.retry()
                    }
                } else {
                    Log.d(TAG, "Blocklist já está atualizada (versão $currentVersion)")
                    Result.success()
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Erro na atualização de blocklist", e)
            Result.retry()
        }
    }

    private suspend fun fetchLatestVersion(): Int? = withContext(Dispatchers.IO) {
        try {
            val url = java.net.URL(BLOCKLIST_VERSION_URL)
            val connection = url.openConnection() as java.net.HttpURLConnection
            connection.connectTimeout = 10000
            connection.readTimeout = 10000
            
            val input = connection.inputStream.bufferedReader()
            val json = input.readText()
            input.close()
            
            // Parse JSON: {"version": 123, "generated_at": "..."}
            val gson = com.google.gson.Gson()
            val versionObj = gson.fromJson(json, VersionResponse::class.java)
            versionObj.version
        } catch (e: Exception) {
            Log.w(TAG, "Falha ao buscar versão da blocklist", e)
            null
        }
    }

    private suspend fun downloadBlocklist(): ByteArray? = withContext(Dispatchers.IO) {
        try {
            val url = java.net.URL(BLOCKLIST_URL)
            val connection = url.openConnection() as java.net.HttpURLConnection
            connection.connectTimeout = 30000
            connection.readTimeout = 60000
            
            val input = connection.inputStream
            val bytes = input.readAllBytes()
            input.close()
            bytes
        } catch (e: Exception) {
            Log.w(TAG, "Falha ao baixar blocklist", e)
            null
        }
    }

    private data class VersionResponse(
        val version: Int,
        val generated_at: String
    )
}