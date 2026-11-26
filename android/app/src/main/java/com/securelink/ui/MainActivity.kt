package com.securelink.ui

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.securelink.R
import com.securelink.core.BrowserHelper
import com.securelink.core.NotificationHelper
import com.securelink.core.SecureLinkEngine
import com.securelink.core.Verdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Tela inicial do app (aberta pelo ícone ou pela notificação de alerta).
 *
 * Fluxo de "continuar usando":
 *  - Se o SecureLink deixou de ser o navegador padrão (ex.: instalou Brave e o definiu como padrão),
 *    o app pergunta: "Quer continuar usando o SecureLink como verificador de links?"
 *  - Se SIM: pergunta qual navegador deve abrir os links (salva só nas configs internas do app,
 *    sem mudar o padrão do Android) e oferece reativar o SecureLink como padrão com 1 toque.
 *  - Se NÃO: registra a recusa por 7 dias para não perguntar de novo.
 */
class MainActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_REPROMPT = "extra_reprompt"
    }

    private val requestDefaultLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { _ ->
            refreshStatus()
        }

    private val requestNotifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { _ -> }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureLinkEngine.ensureInitialized(this)
        NotificationHelper.ensureChannels(this)
        setContentView(R.layout.activity_main)

        requestNotificationPermissionIfNeeded()

        // Na primeira vez, detecta o navegador padrão ANTES de pedir pra virar padrão
        if (!BrowserHelper.hasPromptedOnce(this)) {
            BrowserHelper.detectAndSavePreviousDefaultBrowser(this)
        }

        findViewById<Button>(R.id.btnSetDefault).setOnClickListener {
            promptSetAsDefault()
        }

        findViewById<Button>(R.id.btnChangeBrowser).setOnClickListener {
            showBrowserPicker()
        }

        findViewById<Button>(R.id.btnTestLink).setOnClickListener {
            val input = findViewById<EditText>(R.id.etTestUrl).text.toString().trim()
            if (input.isNotEmpty()) {
                testLink(input)
            }
        }

        refreshStatus()

        // Veio da notificação de alerta?
        val fromNotification = intent?.getBooleanExtra(EXTRA_REPROMPT, false) == true
        maybeShowRepromptDialog(fromNotification)
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
        // Throttling: só mostra de novo se passou o intervalo mínimo
        if (BrowserHelper.shouldShowRepromptDialog(this)) {
            maybeShowRepromptDialog(false)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(EXTRA_REPROMPT, false)) {
            maybeShowRepromptDialog(true)
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                requestNotifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    /**
     * Se o SecureLink não é mais o navegador padrão e o usuário já usou o app antes,
     * mostra o diálogo perguntando se quer continuar usando como verificador de links.
     */
    private fun maybeShowRepromptDialog(fromNotification: Boolean) {
        val isDefault = BrowserHelper.isSecureLinkDefaultBrowser(this)
        val usedBefore = BrowserHelper.hasPromptedOnce(this)
        val declinedRecently = BrowserHelper.hasDeclinedRecently(this, 7L * 24 * 60 * 60 * 1000)

        if (isDefault || !usedBefore || declinedRecently) return
        if (!fromNotification && !BrowserHelper.shouldShowRepromptDialog(this)) return

        BrowserHelper.markRepromptShown(this)
        NotificationHelper.cancelNotDefaultNotification(this)

        AlertDialog.Builder(this)
            .setTitle("🛡️ Continuar usando o SecureLink?")
            .setMessage(
                "Outro aplicativo assumiu como navegador padrão e seus links não estão mais passando " +
                    "pela verificação de golpes do SecureLink.\n\n" +
                    "Quer continuar usando o SecureLink como verificador de segurança dos links?"
            )
            .setPositiveButton("Sim, continuar protegendo") { dialog, _ ->
                dialog.dismiss()
                BrowserHelper.clearDeclined(this)
                // 1) Pergunta qual navegador deve abrir os links (só salva internamente)
                showBrowserPicker(afterPick = {
                    // 2) Depois oferece reativar o SecureLink como padrão com 1 toque
                    promptSetAsDefault()
                })
            }
            .setNegativeButton("Agora não") { dialog, _ ->
                dialog.dismiss()
                BrowserHelper.markDeclined(this)
                refreshStatus()
            }
            .setCancelable(true)
            .show()
    }

    private fun refreshStatus() {
        val isDefault = BrowserHelper.isSecureLinkDefaultBrowser(this)
        val tvStatus = findViewById<TextView>(R.id.tvStatus)
        val btnSetDefault = findViewById<Button>(R.id.btnSetDefault)
        val (checked, blocked) = BrowserHelper.getStats(this)

        if (isDefault) {
            NotificationHelper.cancelNotDefaultNotification(this)
            tvStatus.text = "🛡️ Proteção ATIVA\nTodo link que você clicar (WhatsApp, Telegram, SMS, e-mail) passa pela verificação do SecureLink antes de abrir no seu navegador."
            btnSetDefault.text = "✅ SecureLink já é o navegador padrão"
            btnSetDefault.isEnabled = false
        } else {
            tvStatus.text = "⚠️ Proteção INATIVA\nOutro app está como navegador padrão. Toque no botão abaixo para reativar o SecureLink com 1 toque."
            btnSetDefault.text = "🔒 Reativar proteção (1 toque)"
            btnSetDefault.isEnabled = true
        }

        val target = BrowserHelper.getSavedTargetBrowser(this)
        findViewById<TextView>(R.id.tvTargetBrowser).text =
            if (target != null) "🌐 Seus links abrem no: ${target.label}" else "🌐 Nenhum navegador de destino definido"

        findViewById<TextView>(R.id.tvStats).text =
            "📊 Links verificados: $checked  •  Golpes bloqueados: $blocked"
    }

    private fun promptSetAsDefault() {
        // Salva o navegador anterior antes de pedir para mudar o padrão
        BrowserHelper.detectAndSavePreviousDefaultBrowser(this)
        BrowserHelper.markPromptedOnce(this)
        try {
            requestDefaultLauncher.launch(BrowserHelper.createRequestDefaultBrowserIntent(this))
        } catch (_: Exception) {
            try {
                startActivity(BrowserHelper.createRequestDefaultBrowserIntent(this))
            } catch (_: Exception) {
            }
        }
    }

    private fun showBrowserPicker(afterPick: (() -> Unit)? = null) {
        val browsers = BrowserHelper.getInstalledBrowsers(this)
        if (browsers.isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("Nenhum navegador encontrado")
                .setMessage("Instale um navegador (Chrome, Firefox, Brave, etc.) para que o SecureLink possa abrir os links nele.")
                .setPositiveButton("OK", null)
                .show()
            return
        }

        val names = browsers.map { it.label }.toTypedArray()
        val current = BrowserHelper.getSavedTargetBrowser(this)
        val checkedItem = browsers.indexOfFirst { it.packageName == current?.packageName }.coerceAtLeast(0)

        AlertDialog.Builder(this)
            .setTitle("Para qual navegador os links devem abrir?")
            .setMessage("Essa escolha fica só dentro do SecureLink — não muda o navegador padrão do Android. Os links verificados serão abertos neste app.")
            .setSingleChoiceItems(names, checkedItem) { dialog, which ->
                BrowserHelper.saveTargetBrowser(
                    this,
                    browsers[which].packageName,
                    browsers[which].label
                )
                refreshStatus()
                dialog.dismiss()
                afterPick?.invoke()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun testLink(url: String) {
        val etResult = findViewById<TextView>(R.id.tvTestResult)
        etResult.text = "Analisando..."
        lifecycleScope.launch {
            val result = withContext(Dispatchers.Default) {
                SecureLinkEngine.analyze(url)
            }
            val (emoji, label) = when (result.verdict) {
                Verdict.SAFE -> "✅" to "SEGURO (${result.riskScore}/100)"
                Verdict.SUSPICIOUS -> "⚠️" to "SUSPEITO (${result.riskScore}/100)"
                Verdict.BLOCKED -> "🚫" to "BLOQUEADO (${result.riskScore}/100)"
            }
            val reasons = result.reasons.joinToString("\n") { "• ${it.messagePt}" }
            etResult.text = "$emoji $label\n\n$reasons"
        }
    }
}
