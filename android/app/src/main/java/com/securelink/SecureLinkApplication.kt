package com.securelink

import android.app.Application
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.securelink.core.NotificationHelper
import com.securelink.core.SecureLinkEngine
import com.securelink.worker.BlocklistUpdateWorker
import com.securelink.worker.DefaultBrowserCheckWorker
import java.util.concurrent.TimeUnit

class SecureLinkApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Inicializa motor de análise (Kotlin puro ou Rust nativo se disponível)
        SecureLinkEngine.init(this)
        Log.d("SecureLink", "Engine inicializado. Nativo disponível: ${SecureLinkEngine.isNativeAvailable()}")

        NotificationHelper.ensureChannels(this)

        // Agenda atualização periódica de blocklist (a cada 24h)
        scheduleBlocklistUpdate()

        // Agenda verificação periódica se o SecureLink ainda é o navegador padrão (a cada 12h)
        scheduleDefaultBrowserCheck()
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

    private fun scheduleDefaultBrowserCheck() {
        // WorkManager exige mínimo de 15 minutos; usamos 12h
        val checkRequest = PeriodicWorkRequestBuilder<DefaultBrowserCheckWorker>(
            12, TimeUnit.HOURS
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiresCharging(false)
                    .build()
            )
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            DefaultBrowserCheckWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            checkRequest
        )
    }
}
