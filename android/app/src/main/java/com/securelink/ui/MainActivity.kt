package com.securelink.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelink.R
import com.securelink.core.SecureLinkEngine
import com.securelink.core.AnalysisResult
import com.securelink.core.Verdict
import com.securelink.databinding.ActivityMainBinding
import kotlinx.coroutines.launch

/**
 * Activity principal - atua como navegador padrão para interceptar links.
 * Quando o usuário clica em um link no WhatsApp/Telegram/SMS/Email,
 * o Android abre esta activity primeiro.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val engine = SecureLinkEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Verifica se engine nativo está disponível
        if (!engine.isAvailable()) {
            Log.e("MainActivity", "Engine nativo não disponível")
            finish()
            return
        }

        // Processa intent recebida (link clicado)
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
            
            // Verificação rápida primeiro (sem UI se seguro)
            val quickScore = engine.quickCheck(url)
            
            if (quickScore < 30) {
                // Provavelmente seguro - abre direto no navegador real
                openInRealBrowser(url)
                finish()
                return
            }
            
            // Análise completa com UI
            showVerdictUi(url)
        } else {
            // Aberto diretamente (launcher) - mostra tela inicial
            showHomeScreen()
        }
    }

    private fun showVerdictUi(url: String) {
        binding.progressBar.isVisible = true
        binding.tvStatus.text = "Analisando link..."
        
        lifecycleScope.launch {
            val jsonResult = engine.analyzeUrl(url)
            val result = com.securelink.core.AnalysisResultParser.parse(jsonResult)
            
            runOnUiThread {
                binding.progressBar.isVisible = false
                renderVerdict(result, url)
            }
        }
    }

    private fun renderVerdict(result: AnalysisResult, originalUrl: String) {
        val verdictColor = when (result.verdict) {
            Verdict.SAFE -> 0xFF2E7D32.toInt()      // Verde
            Verdict.SUSPICIOUS -> 0xFFF9A825.toInt() // Amarelo
            Verdict.BLOCKED -> 0xFFC62828.toInt()    // Vermelho
        }
        
        binding.verdictCard.setCardBackgroundColor(verdictColor)
        binding.tvVerdictLabel.text = result.verdict.name
        binding.tvVerdictLabel.setTextColor(0xFFFFFFFF.toInt())
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
        // Força abertura no navegador real (não neste app)
        intent.setPackage(null) 
        try {
            startActivity(intent)
        } catch (e: Exception) {
            // Fallback: deixa o sistema escolher
            startActivity(Intent.createChooser(intent, "Abrir com"))
        }
        finish()
    }

    private fun openOfficialSite(brand: String) {
        // Busca domínio oficial da marca nas preferências/config
        val officialUrl = getOfficialDomain(brand) ?: "https://google.com/search?q=$brand"
        openInRealBrowser(officialUrl)
    }

    private fun getOfficialDomain(brand: String): String? {
        // TODO: buscar no repositório de marcas
        return when (brand.lowercase()) {
            "cacau show" -> "https://cacaushow.com.br"
            "nubank" -> "https://nubank.com.br"
            "apple" -> "https://apple.com"
            "google" -> "https://google.com"
            "microsoft" -> "https://microsoft.com"
            "amazon" -> "https://amazon.com.br"
            "mercado livre" -> "https://mercadolivre.com.br"
            else -> null
        }
    }

    private fun reportFalsePositive(url: String) {
        // TODO: implementar envio de relato (opcional, anônimo)
        Log.d("MainActivity", "Falso positivo reportado: $url")
    }

    private fun showHomeScreen() {
        binding.verdictCard.isVisible = false
        binding.tvStatus.text = "Pronto para verificar links"
        binding.tvUrl.text = ""
        // Mostra instruções de como usar
    }
}