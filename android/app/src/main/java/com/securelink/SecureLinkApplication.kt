package com.securelink

import android.app.Application
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.securelink.core.SecureLinkEngine
import com.securelink.worker.BlocklistUpdateWorker
import java.util.concurrent.TimeUnit

class SecureLinkApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Inicializa motor de análise (Kotlin puro ou Rust nativo se disponível)
        SecureLinkEngine.init(this)
        Log.d("SecureLink", "Engine inicializado. Nativo disponível: ${SecureLinkEngine.isNativeAvailable()}")

        // Agenda atualização periódica de blocklist (a cada 24h)
        scheduleBlocklistUpdate()
    }

    private fun scheduleBlocklistUpdate() {
        val updateRequest = PeriodicWorkRequestBuilder<BlocklistUpdateWorker>(
            24, TimeUnit.HOURS
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresCharging(false)
                    .build()
            )
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "blocklist_update",
            ExistingPeriodicWorkPolicy.KEEP,
            updateRequest
        )
    }
}
