package com.securelink.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securelink.R
import com.securelink.core.SecureLinkEngine
import com.securelink.ui.MainActivity

/**
 * Foreground Service para verificação de URLs em background (auto-scan)
 * Roda quando o usuário clica em link e o app não precisa mostrar UI se for seguro
 */
class UrlCheckService : Service() {

    private const val TAG = "UrlCheckService"
    private const val CHANNEL_ID = "url_check_channel"
    private const val NOTIFICATION_ID = 1001

    private var notificationManager: NotificationManager? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val url = intent?.getStringExtra("url") ?: return START_NOT_STICKY
        val callbackIntent = intent.getParcelableExtra<PendingIntent>("callback")

        // Verificação rápida
        val score = SecureLinkEngine.quickCheck(url)

        if (score < 30) {
            // Seguro - executa callback para abrir no navegador real
            callbackIntent?.send()
            Log.d(TAG, "URL segura ($score): $url - abrindo direto")
        } else {
            // Suspeito/Perigoso - abre app para mostrar veredito
            val mainIntent = Intent(this, MainActivity::class.java).apply {
                action = Intent.ACTION_VIEW
                data = android.net.Uri.parse(url)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            startActivity(mainIntent)
            Log.d(TAG, "URL suspeita ($score): $url - abrindo app para veredito")
        }

        stopSelf()
        return START_NOT_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Verificação de Links",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Notificações de verificação de links em background"
                setShowBadge(false)
            }
            notificationManager?.createNotificationChannel(channel)
        }
    }

    private fun showCheckingNotification(url: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                action = Intent.ACTION_VIEW
                data = android.net.Uri.parse(url)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle("Verificando link...")
            .setContentText(url.take(50))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setContentIntent(contentIntent)
            .setAutoCancel(false)
            .setOngoing(true)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        notificationManager?.cancel(NOTIFICATION_ID)
    }
}