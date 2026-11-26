package com.securelink.ui

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.text.format.Formatter
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.card.MaterialCardView
import com.securelink.R
import com.securelink.core.BrowserHelper

/**
 * Tela de alerta (pop-up) exibida SOMENTE quando o link é suspeito ou bloqueado.
 * Opções: abrir site oficial, abrir mesmo assim no navegador real, ou cancelar.
 */
class VerdictActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_verdict)

        val result = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getSerializableExtra(LinkInterceptorActivity.EXTRA_RESULT, SerializableAnalysisResult::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getSerializableExtra(LinkInterceptorActivity.EXTRA_RESULT) as? SerializableAnalysisResult
        }
        val originalUrl = intent.getStringExtra("extra_original_url")
            ?: result?.originalUrl
            ?: ""

        if (result == null) {
            finish()
            return
        }

        setupUI(result, originalUrl)
    }

    private fun setupUI(result: SerializableAnalysisResult, originalUrl: String) {
        val isBlocked = result.verdict == "BLOCKED"
        val color = when (result.verdict) {
            "BLOCKED" -> 0xFFC62828.toInt()
            "SUSPICIOUS" -> 0xFFF9A825.toInt()
            else -> 0xFF2E7D32.toInt()
        }
        val emoji = when (result.verdict) {
            "BLOCKED" -> "🚫"
            "SUSPICIOUS" -> "⚠️"
            else -> "✅"
        }
        val label = when (result.verdict) {
            "BLOCKED" -> "LINK BLOQUEADO — PERIGO!"
            "SUSPICIOUS" -> "LINK SUSPEITO"
            else -> "LINK SEGURO"
        }

        val cardHeader = findViewById<View>(R.id.verdictHeader)
        val tvVerdict = findViewById<TextView>(R.id.tvVerdictLabel)
        val tvUrl = findViewById<TextView>(R.id.tvUrl)
        val tvScore = findViewById<TextView>(R.id.tvRiskScore)
        val tvReasons = findViewById<TextView>(R.id.tvReasons)
        val btnOfficial = findViewById<Button>(R.id.btnOpenOfficial)
        val btnOpenAnyway = findViewById<Button>(R.id.btnOpenAnyway)
        val btnCancel = findViewById<Button>(R.id.btnCancel)
        val tvBrandWarning = findViewById<TextView>(R.id.tvBrandWarning)

        cardHeader.setBackgroundColor(color)
        tvVerdict.text = "$emoji $label"
        tvUrl.text = originalUrl
        tvScore.text = "Nível de risco: ${result.riskScore}/100"

        val reasonsText = result.reasons.joinToString("\n") { line ->
            val parts = line.split("|", limit = 3)
            val msg = if (parts.size >= 3) parts[2] else line
            "• $msg"
        }
        tvReasons.text = reasonsText

        // Site oficial (se detectou marca personificada)
        val officialDomain = result.officialDomain
        if (result.impersonatedBrand != null && !officialDomain.isNullOrBlank()) {
            tvBrandWarning.visibility = View.VISIBLE
            tvBrandWarning.text = "Este link parece imitar: ${result.impersonatedBrand}"
            btnOfficial.visibility = View.VISIBLE
            btnOfficial.text = "Abrir site oficial (${officialDomain})"
            btnOfficial.setOnClickListener {
                BrowserHelper.openInTargetBrowser(applicationContext, "https://$officialDomain")
                finish()
            }
        } else {
            btnOfficial.visibility = View.GONE
            tvBrandWarning.visibility = View.GONE
        }

        btnOpenAnyway.setOnClickListener {
            BrowserHelper.openInTargetBrowser(applicationContext, originalUrl)
            finish()
        }

        btnCancel.setOnClickListener {
            finish()
        }
    }
}
