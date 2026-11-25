package com.securelink.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelink.R
import com.securelink.core.SecureLinkEngine
import com.securelink.core.AnalysisResult
import com.securelink.core.Verdict
import kotlinx.coroutines.launch

/**
 * Activity principal - atua como navegador padrão para interceptar links.
 * Quando o usuário clica em um link no WhatsApp/Telegram/SMS/Email,
 * o Android abre esta activity primeiro.
 */
class MainActivity : AppCompatActivity() {

    private val engine = SecureLinkEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        val action = intent.action
        val data = intent.data

        if (action == Intent.ACTION_VIEW && data != null) {
            val url = data.toString()
            Log.d("MainActivity", "Link interceptado: $url")
            analyzeAndShow(url)
        } else {
            showHomeScreen()
        }
    }

    private fun analyzeAndShow(url: String) {
        lifecycleScope.launch {
            val result = engine.analyze(url)
            runOnUiThread { renderVerdict(result, url) }
        }
    }

    private fun renderVerdict(result: AnalysisResult, originalUrl: String) {
        val tvVerdict = findViewById<android.widget.TextView>(R.id.tvVerdictLabel)
        val tvUrl = findViewById<android.widget.TextView>(R.id.tvUrl)
        val tvScore = findViewById<android.widget.TextView>(R.id.tvRiskScore)
        val tvReasons = findViewById<android.widget.TextView>(R.id.tvReasons)
        val btnOpen = findViewById<android.widget.Button>(R.id.btnOpenAnyway)
        val btnOfficial = findViewById<android.widget.Button>(R.id.btnOpenOfficial)
        val card = findViewById<android.view.View>(R.id.verdictCard)

        val (color, emoji, label) = when (result.verdict) {
            Verdict.SAFE -> Triple(0xFF2E7D32.toInt(), "✅", "SEGURO")
            Verdict.SUSPICIOUS -> Triple(0xFFF9A825.toInt(), "⚠️", "SUSPEITO")
            Verdict.BLOCKED -> Triple(0xFFC62828.toInt(), "🚫", "BLOQUEADO - PERIGO!")
        }

        card.setBackgroundColor(color)
        tvVerdict.text = "$emoji $label"
        tvVerdict.setTextColor(0xFFFFFFFF.toInt())
        tvUrl.text = originalUrl
        tvScore.text = "Risco: ${result.riskScore}/100"

        val reasonsText = result.reasons.joinToString("\n") { "• ${it.messagePt}" }
        tvReasons.text = reasonsText

        btnOpen.setOnClickListener { openInRealBrowser(originalUrl) }

        if (result.impersonatedBrand != null) {
            btnOfficial.visibility = View.VISIBLE
            btnOfficial.setOnClickListener { openOfficialSite(result.impersonatedBrand!!) }
        } else {
            btnOfficial.visibility = View.GONE
        }

        card.visibility = View.VISIBLE
    }

    private fun openInRealBrowser(url: String) {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        try {
            startActivity(intent)
        } catch (e: Exception) {
            startActivity(Intent.createChooser(intent, "Abrir com"))
        }
        finish()
    }

    private fun openOfficialSite(brand: String) {
        val officialUrl = when (brand.lowercase()) {
            "cacau show" -> "https://cacaushow.com.br"
            "nubank" -> "https://nubank.com.br"
            "apple" -> "https://apple.com"
            "google" -> "https://google.com"
            "microsoft" -> "https://microsoft.com"
            "amazon" -> "https://amazon.com.br"
            "mercado livre" -> "https://mercadolivre.com.br"
            else -> "https://www.google.com/search?q=$brand+site+oficial"
        }
        openInRealBrowser(officialUrl)
    }

    private fun showHomeScreen() {
        setContentView(R.layout.activity_main)
        findViewById<android.widget.TextView>(R.id.tvStatus)?.text = "SecureLink ativo ✅\n\nDefina como navegador padrão em:\nConfigurações → Apps → Navegador padrão → SecureLink\n\nDepois clique em qualquer link no WhatsApp e veja a verificação!"
    }
}
