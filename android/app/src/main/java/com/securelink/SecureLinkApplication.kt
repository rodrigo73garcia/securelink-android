package com.securelink

import android.app.Application
import android.content.Context
import android.util.Log
import com.securelink.core.SecureLinkEngine
import com.securelink.data.preferences.PreferencesRepository
import com.securelink.data.repository.BlocklistRepository
import com.securelink.di.AppModule
import dagger.hilt.android.HiltAndroidApp
import dagger.hilt.android.EntryPointAccessors
import javax.inject.Inject

@HiltAndroidApp
class SecureLinkApplication : Application() {

    @Inject
    lateinit var preferencesRepository: PreferencesRepository

    @Inject
    lateinit var blocklistRepository: BlocklistRepository

    override fun onCreate() {
        super.onCreate()
        
        // Inicializa Timber para logging
        if (BuildConfig.DEBUG) {
            timber.Timber.plant(timber.Timber.DebugTree())
        }

        // Inicializa engine nativo
        initNativeEngine()
        
        // Carrega blocklist do assets
        loadBlocklistFromAssets()
        
        // Agenda atualização periódica de blocklist
        scheduleBlocklistUpdate()
    }

    private fun initNativeEngine() {
        val config = SecureLinkConfig(
            brands = preferencesRepository.getBrands(),
            typoThreshold = preferencesRepository.getTypoThreshold(),
            minDomainAgeDays = preferencesRepository.getMinDomainAgeDays(),
            criticalDomainAgeDays = preferencesRepository.getCriticalDomainAgeDays(),
            suspiciousTlds = preferencesRepository.getSuspiciousTlds(),
            phishingKeywords = preferencesRepository.getPhishingKeywords(),
            enableRdap = preferencesRepository.isRdapEnabled(),
            enableUnshorten = preferencesRepository.isUnshortenEnabled(),
            rdapTimeoutMs = preferencesRepository.getRdapTimeoutMs(),
            unshortenTimeoutMs = preferencesRepository.getUnshortenTimeoutMs()
        )
        
        val configJson = com.google.gson.Gson().toJson(config)
        val success = SecureLinkEngine.init(configJson)
        
        if (success) {
            timber.Timber.d("SecureLink Engine inicializado com sucesso")
        } else {
            timber.Timber.e("Falha ao inicializar SecureLink Engine")
        }
    }

    private fun loadBlocklistFromAssets() {
        // Copia bloom filter do assets para arquivos internos se não existir
        val destFile = fileDir.resolve("blocklist.bloom")
        if (!destFile.exists()) {
            try {
                assets.open("blocklist.bloom").use { input ->
                    destFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                val success = SecureLinkEngine.loadBloomFilter(destFile.absolutePath)
                if (success) {
                    timber.Timber.d("Bloom filter carregado do assets")
                } else {
                    timber.Timber.w("Falha ao carregar bloom filter do assets")
                }
            } catch (e: Exception) {
                timber.Timber.e(e, "Erro ao copiar bloom filter do assets")
            }
        } else {
            // Carrega do arquivo interno
            SecureLinkEngine.loadBloomFilter(destFile.absolutePath)
        }
    }

    private fun scheduleBlocklistUpdate() {
        val workManager = androidx.work.WorkManager.getInstance(this)
        val updateRequest = androidx.work.PeriodicWorkRequestBuilder<BlocklistUpdateWorker>(
            24, java.util.concurrent.TimeUnit.HOURS
        )
            .setConstraints(
                androidx.work.Constraints.Builder()
                    .setRequiredNetworkType(androidx.work.NetworkType.CONNECTED)
                    .setRequiresCharging(false)
                    .build()
            )
            .build()
        
        workManager.enqueueUniquePeriodicWork(
            "blocklist_update",
            androidx.work.ExistingPeriodicWorkPolicy.KEEP,
            updateRequest
        )
    }
}

// Data class para configuração (serializada para JSON)
data class SecureLinkConfig(
    val brands: List<BrandConfig>,
    val typoThreshold: Int,
    val minDomainAgeDays: Int,
    val criticalDomainAgeDays: Int,
    val suspiciousTlds: List<String>,
    val phishingKeywords: List<String>,
    val enableRdap: Boolean,
    val enableUnshorten: Boolean,
    val rdapTimeoutMs: Long,
    val unshortenTimeoutMs: Long
)

data class BrandConfig(
    val name: String,
    val officialDomain: String,
    val altDomains: List<String>,
    val keywords: List<String>,
    val priority: Int
)