package com.securelink.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelink.R
import com.securelink.core.SecureLinkEngine
import com.securelink.core.AnalysisResultParser
import kotlinx.coroutines.launch

/**
 * Activity para receber links compartilhados (Share → SecureLink).
 * Útil para links abertos em WebViews internas (Instagram, Facebook, etc.)
 * onde o navegador padrão não intercepta.
 */
class ShareTargetActivity : AppCompatActivity() {

    private val engine = SecureLinkEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_share_target)

        if (!engine.isAvailable()) {
            finish()
            return
        }

        handleSharedIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleSharedIntent(intent)
    }

    private fun handleSharedIntent(intent: Intent) {
        val action = intent.action
        val type = intent.type

        if (Intent.ACTION_SEND == action && type != null && type.startsWith("text/")) {
            val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT) ?: ""
            val url = extractUrl(sharedText)
            
            if (url.isNotEmpty()) {
                Log.d("ShareTarget", "Link recebido via share: $url")
                analyzeAndShow(url)
            } else {
                showError("Nenhum link válido encontrado no texto compartilhado")
            }
        } else {
            finish()
        }
    }

    private fun extractUrl(text: String): String {
        // Regex simples para extrair primeira URL do texto
        val urlRegex = """(https?://[^\s]+)""".toRegex()
        return urlRegex.find(text)?.value ?: ""
    }

    private fun analyzeAndShow(url: String) {
        findViewById<android.widget.ProgressBar>(R.id.progressBar).isVisible = true
        findViewById<android.widget.TextView>(R.id.tvStatus).text = "Analisando link compartilhado..."
        
        lifecycleScope.launch {
            val jsonResult = engine.analyzeUrl(url)
            val result = AnalysisResultParser.parse(jsonResult)
            
            runOnUiThread {
                findViewById<android.widget.ProgressBar>(R.id.progressBar).isVisible = false
                renderResult(result, url)
            }
        }
    }

    private fun renderResult(result: com.securelink.core.AnalysisResult, url: String) {
        val verdictColor = when (result.verdict) {
            com.securelink.core.Verdict.SAFE -> 0xFF2E7D32.toInt()
            com.securelink.core.Verdict.SUSPICIOUS -> 0xFFF9A825.toInt()
            com.securelink.core.Verdict.BLOCKED -> 0xFFC62828.toInt()
        }
        
        val verdictCard = findViewById<com.google.android.material.card.MaterialCardView>(R.id.verdictCard)
        verdictCard.setCardBackgroundColor(verdictColor)
        verdictCard.isVisible = true
        
        findViewById<android.widget.TextView>(R.id.tvVerdictLabel).text = result.verdict.name
        findViewById<android.widget.TextView>(R.id.tvUrl).text = url
        findViewById<android.widget.TextView>(R.id.tvRiskScore).text = "Score: ${result.riskScore}/100"
        
        // Botão abrir no navegador
        findViewById<com.google.android.material.button.MaterialButton>(R.id.btnOpenInBrowser).setOnClickListener {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                startActivity(intent)
            } catch (e: Exception) {
                startActivity(Intent.createChooser(intent, "Abrir com"))
            }
            finish()
        }
        
        // Botão fechar
        findViewById<com.google.android.material.button.MaterialButton>(R.id.btnClose).setOnClickListener {
            finish()
        }
    }

    private fun showError(message: String) {
        findViewById<android.widget.TextView>(R.id.tvStatus).text = message
        findViewById<android.widget.ProgressBar>(R.id.progressBar).isVisible = false
        findViewById<com.google.android.material.button.MaterialButton>(R.id.btnClose).setOnClickListener { finish() }
    }
}