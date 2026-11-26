package com.securelink.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.securelink.core.BrowserHelper
import com.securelink.core.NotificationHelper

/**
 * Worker periódico (12h) + no boot: verifica se o SecureLink ainda é o navegador padrão.
 * Se deixou de ser (ex.: usuário instalou outro navegador e o definiu como padrão),
 * envia uma notificação perguntando se quer continuar usando o SecureLink como verificador.
 */
class DefaultBrowserCheckWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "DefaultBrowserCheck"
        const val WORK_NAME = "default_browser_check"
        private const val DECLINE_COOLDOWN_MS = 7L * 24 * 60 * 60 * 1000 // 7 dias
    }

    override suspend fun doWork(): Result {
        return try {
            val ctx = applicationContext
            val isDefault = BrowserHelper.isSecureLinkDefaultBrowser(ctx)
            Log.d(TAG, "SecureLink é navegador padrão? $isDefault")

            if (isDefault) {
                NotificationHelper.cancelNotDefaultNotification(ctx)
                Result.success()
            } else {
                // Só avisa se o usuário já usou o app antes (já fez o onboarding)
                val usedBefore = BrowserHelper.hasPromptedOnce(ctx)
                val declined = BrowserHelper.hasDeclinedRecently(ctx, DECLINE_COOLDOWN_MS)

                if (usedBefore && !declined) {
                    Log.d(TAG, "Não é mais padrão e usuário já usou -> enviando notificação")
                    NotificationHelper.showNotDefaultNotification(ctx)
                } else {
                    Log.d(TAG, "Não é padrão, mas usedBefore=$usedBefore declined=$declined -> sem notificação")
                }
                Result.success()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Erro no check: ${e.message}")
            Result.success()
        }
    }
}
