package com.securelink.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.WorkManager
import com.securelink.worker.BlocklistUpdateWorker

/**
 * Receiver para BOOT_COMPLETED - reativa workers após reinicialização
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_BOOT_COMPLETED == intent.action) {
            Log.d("BootReceiver", "Boot completed - reagendando workers")
            
            val workManager = WorkManager.getInstance(context)
            val updateRequest = androidx.work.PeriodicWorkRequestBuilder<BlocklistUpdateWorker>(
                24, java.util.concurrent.TimeUnit.HOURS
            )
                .setConstraints(
                    androidx.work.Constraints.Builder()
                        .setRequiredNetworkType(androidx.work.NetworkType.CONNECTED)
                        .build()
                )
                .build()
            
            workManager.enqueueUniquePeriodicWork(
                "blocklist_update",
                androidx.work.ExistingPeriodicWorkPolicy.KEEP,
                updateRequest
            )
            
            Log.d("BootReceiver", "Workers reagendados com sucesso")
        }
    }
}