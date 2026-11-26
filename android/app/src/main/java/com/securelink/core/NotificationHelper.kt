package com.securelink.core

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.securelink.R
import com.securelink.ui.MainActivity

/**
 * Cria canais e envia notificações do SecureLink.
 */
object NotificationHelper {

    const val CHANNEL_ALERTS = "securelink_alerts"
    const val NOTIF_ID_NOT_DEFAULT = 1001

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ALERTS,
                "Alertas de proteção",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Avisos quando o SecureLink deixa de ser o navegador padrão"
            }
            nm?.createNotificationChannel(channel)
        }
    }

    /**
     * Notificação avisando que o SecureLink não é mais o navegador padrão e perguntando
     * se o usuário quer continuar usando ele como verificador de links.
     * Ao tocar, abre o MainActivity com extra_reprompt=true.
     */
    fun showNotDefaultNotification(context: Context) {
        ensureChannels(context)

        val intent = Intent(context, MainActivity::class.java).apply {
            action = Intent.ACTION_VIEW
            putExtra(MainActivity.EXTRA_REPROMPT, true)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            NOTIF_ID_NOT_DEFAULT,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_shield_check)
            .setContentTitle("🛡️ SecureLink não está mais como navegador padrão")
            .setContentText("Outro app (ex.: um navegador novo) assumiu os links. Quer continuar usando o SecureLink como verificador de segurança? Toque aqui.")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("Outro aplicativo assumiu como navegador padrão e os links não estão mais passando pela verificação do SecureLink. Toque para continuar protegido e escolher para qual navegador os links devem abrir.")
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val nm = context.getSystemService(NotificationManager::class.java)
        nm?.notify(NOTIF_ID_NOT_DEFAULT, notification)
    }

    fun cancelNotDefaultNotification(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm?.cancel(NOTIF_ID_NOT_DEFAULT)
    }
}
