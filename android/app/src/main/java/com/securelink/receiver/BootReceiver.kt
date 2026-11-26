package com.securelink.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.securelink.worker.BlocklistUpdateWorker
import com.securelink.worker.DefaultBrowserCheckWorker
import java.util.concurrent.TimeUnit

/**
 * Receiver para BOOT_COMPLETED - reativa workers após reinicialização
 * e dispara uma checagem imediata se o SecureLink ainda é o navegador padrão.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_BOOT_COMPLETED == intent.action) {
            Log.d("BootReceiver", "Boot completed - reagendando workers")

            val workManager = WorkManager.getInstance(context)

            // Blocklist a cada 24h (precisa de rede)
            val updateRequest = PeriodicWorkRequestBuilder<BlocklistUpdateWorker>(
                24, TimeUnit.HOURS
            )
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .build()

            workManager.enqueueUniquePeriodicWork(
                "blocklist_update",
                ExistingPeriodicWorkPolicy.KEEP,
                updateRequest
            )

            // Check de navegador padrão a cada 12h
            val checkRequest = PeriodicWorkRequestBuilder<DefaultBrowserCheckWorker>(
                12, TimeUnit.HOURS
            )
                .setConstraints(
                    Constraints.Builder()
                        .setRequiresCharging(false)
                        .build()
                )
                .build()

            workManager.enqueueUniquePeriodicWork(
                DefaultBrowserCheckWorker.WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                checkRequest
            )

            // Check imediato no boot (rápido, sem rede)
            workManager.enqueue(
                OneTimeWorkRequestBuilder<DefaultBrowserCheckWorker>()
                    .setConstraints(
                        Constraints.Builder()
                            .setRequiresCharging(false)
                            .build()
                    )
                    .build()
            )

            Log.d("BootReceiver", "Workers reagendados com sucesso")
        }
    }
}
