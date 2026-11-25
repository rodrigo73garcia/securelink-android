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
import com.securelink.databinding.ActivityVerdictBinding
import kotlinx.coroutines.launch

/**
 * Activity de veredito - mostra análise detalhada do link
 * Pode ser aberta diretamente ou via MainActivity
 */
class VerdictActivity : AppCompatActivity() {

    private lateinit var binding: ActivityVerdictBinding
    private val engine = SecureLinkEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityVerdictBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (!engine.isAvailable()) {
            finish()
            return
        }

        val url = intent.data?.toString() ?: intent.getStringExtra("url") ?: ""
        if (url.isEmpty()) {
            finish()
            return
        }

        analyzeUrl(url)
    }

    private fun analyzeUrl(url: String) {
        binding.progressBar.isVisible = true
        binding.tvStatus.text = getString(R.string.checking_link)
        
        lifecycleScope.launch {
            val jsonResult = engine.analyzeUrl(url)
            val result = AnalysisResultParser.parse(jsonResult)
            
            runOnUiThread {
                binding.progressBar.isVisible = false
                renderVerdict(result, url)
            }
        }
    }

    private fun renderVerdict(result: com.securelink.core.AnalysisResult, originalUrl: String) {
        val verdictColor = when (result.verdict) {
            com.securelink.core.Verdict.SAFE -> 0xFF2E7D32.toInt()
            com.securelink.core.Verdict.SUSPICIOUS -> 0xFFF9A825.toInt()
            com.securelink.core.Verdict.BLOCKED -> 0xFFC62828.toInt()
        }
        
        binding.verdictCard.setCardBackgroundColor(verdictColor)
        binding.tvVerdictLabel.text = when (result.verdict) {
            com.securelink.core.Verdict.SAFE -> getString(R.string.verdict_safe)
            com.securelink.core.Verdict.SUSPICIOUS -> getString(R.string.verdict_suspicious)
            com.securelink.core.Verdict.BLOCKED -> getString(R.string.verdict_blocked)
        }
        binding.tvUrl.text = originalUrl
        binding.tvRiskScore.text = "Score: ${result.riskScore}/100"
        
        // Motivos
        binding.reasonsContainer.removeAllViews()
        for (reason in result.reasons) {
            val reasonView = layoutInflater.inflate(R.layout.item_reason, binding.reasonsContainer, false)
            reasonView.tvReasonCode.text = reason.code
            reasonView.tvReasonMessage.text = reason.messagePt
            reasonView.tvReasonSeverity.text = reason.severity.name
            binding.reasonsContainer.addView(reasonView)
        }
        
        // Ações
        binding.btnOpenAnyway.setOnClickListener { openInRealBrowser(originalUrl) }
        binding.btnOpenOfficial.setOnClickListener { 
            result.impersonatedBrand?.let { brand ->
                openOfficialSite(brand)
            }
        }
        binding.btnReportFalsePositive.setOnClickListener { reportFalsePositive(originalUrl) }
        
        binding.verdictCard.isVisible = true
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
            "itau", "itáu" -> "https://itau.com.br"
            "bb", "banco do brasil" -> "https://bb.com.br"
            "bradesco" -> "https://bradesco.com.br"
            "santander" -> "https://santander.com.br"
            "caixa" -> "https://caixa.gov.br"
            "magazine luiza", "magalu" -> "https://magazineluiza.com.br"
            "americanas" -> "https://americanas.com.br"
            "correios" -> "https://correios.com.br"
            "gov.br" -> "https://gov.br"
            "receita federal" -> "https://receita.fazenda.gov.br"
            "inss" -> "https://inss.gov.br"
            else -> "https://google.com/search?q=${Uri.encode(brand)}"
        }
        openInRealBrowser(officialUrl)
    }

    private fun reportFalsePositive(url: String) {
        Log.d("VerdictActivity", "Falso positivo reportado: $url")
        // TODO: implementar envio anônimo (opcional)
    }
}