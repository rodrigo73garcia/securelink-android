package com.securelink.ui

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelink.R
import com.securelink.core.BrowserHelper
import com.securelink.core.SecureLinkEngine
import com.securelink.core.Verdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Tela inicial do app (aberta pelo ícone).
 * - Na primeira abertura, detecta o navegador atual e pede 1 toque para virar o padrão.
 * - Mostra status da proteção, navegador de destino, botão para trocar, e teste manual de link.
 */
class MainActivity : AppCompatActivity() {

    private val requestDefaultLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { _ ->
            refreshStatus()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureLinkEngine.ensureInitialized(this)
        setContentView(R.layout.activity_main)

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
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    private fun refreshStatus() {
        val isDefault = BrowserHelper.isSecureLinkDefaultBrowser(this)
        val tvStatus = findViewById<TextView>(R.id.tvStatus)
        val btnSetDefault = findViewById<Button>(R.id.btnSetDefault)
        val (checked, blocked) = BrowserHelper.getStats(this)

        if (isDefault) {
            tvStatus.text = "🛡️ Proteção ATIVA\nTodo link que você clicar (WhatsApp, Telegram, SMS, e-mail) passa pela verificação do SecureLink antes de abrir no seu navegador."
            btnSetDefault.text = "✅ SecureLink já é o navegador padrão"
            btnSetDefault.isEnabled = false
        } else {
            tvStatus.text = "⚠️ Proteção INATIVA\nToque no botão abaixo para ativar com 1 toque."
            btnSetDefault.text = "🔒 Ativar proteção (1 toque)"
            btnSetDefault.isEnabled = true
        }

        val target = BrowserHelper.getSavedTargetBrowser(this)
        findViewById<TextView>(R.id.tvTargetBrowser).text =
            if (target != null) "🌐 Seus links abrem no: ${target.label}" else "🌐 Nenhum navegador detectado ainda"

        findViewById<TextView>(R.id.tvStats).text =
            "📊 Links verificados: $checked  •  Golpes bloqueados: $blocked"
    }

    private fun promptSetAsDefault() {
        // Salva o navegador anterior antes de pedir para mudar o padrão
        BrowserHelper.detectAndSavePreviousDefaultBrowser(this)
        BrowserHelper.markPromptedOnce(this)
        try {
            requestDefaultLauncher.launch(BrowserHelper.createRequestDefaultBrowserIntent(this))
        } catch (e: Exception) {
            try {
                startActivity(BrowserHelper.createRequestDefaultBrowserIntent(this))
            } catch (_: Exception) {
            }
        }
    }

    private fun showBrowserPicker() {
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
            .setTitle("Escolha seu navegador")
            .setSingleChoiceItems(names, checkedItem) { dialog, which ->
                BrowserHelper.saveTargetBrowser(
                    this,
                    browsers[which].packageName,
                    browsers[which].label
                )
                refreshStatus()
                dialog.dismiss()
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
