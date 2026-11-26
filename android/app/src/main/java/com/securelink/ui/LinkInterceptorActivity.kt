package com.securelink.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import com.securelink.core.BrowserHelper
import com.securelink.core.SecureLinkEngine
import com.securelink.core.Verdict

/**
 * Activity invisível (transparente, sem UI) que intercepta links http/https quando o
 * SecureLink está como navegador padrão.
 *
 * - Link SEGURO (score < 30): redireciona direto para o navegador real do usuário,
 *   sem mostrar nenhuma tela (o app não aparece).
 * - Link SUSPEITO/BLOQUEADO: abre a VerdictActivity em pop-up pedindo confirmação.
 */
class LinkInterceptorActivity : android.app.Activity() {

    companion object {
        private const val TAG = "LinkInterceptor"
        const val EXTRA_RESULT = "extra_analysis_result"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureLinkEngine.ensureInitialized(applicationContext)

        val data = intent?.data
        if (intent?.action == Intent.ACTION_VIEW && data != null) {
            val url = data.toString()
            Log.d(TAG, "Link interceptado: $url")
            handleLink(url)
        } else {
            // Sem URL, abre a home do app
            startActivity(Intent(this, MainActivity::class.java))
            finish()
            overridePendingTransition(0, 0)
        }
    }

    private fun handleLink(url: String) {
        val result = SecureLinkEngine.analyze(url)
        BrowserHelper.recordLinkCheck(
            applicationContext,
            result.verdict == Verdict.SUSPICIOUS || result.verdict == Verdict.BLOCKED
        )

        if (result.verdict == Verdict.SAFE) {
            // Link legítimo: abre direto no navegador real, sem mostrar nada
            Log.d(TAG, "Link seguro ($url, score=${result.riskScore}) -> abrindo no navegador do usuário")
            BrowserHelper.openInTargetBrowser(applicationContext, url)
            finish()
            overridePendingTransition(0, 0)
        } else {
            // Link suspeito/bloqueado: mostra pop-up de alerta
            Log.d(TAG, "Link suspeito ($url, score=${result.riskScore}) -> abrindo alerta")
            val intent = Intent(this, VerdictActivity::class.java).apply {
                putExtra(EXTRA_RESULT, toSerializable(result))
                putExtra("extra_original_url", url)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
            finish()
            overridePendingTransition(0, 0)
        }
    }

    private fun toSerializable(r: com.securelink.core.AnalysisResult): SerializableAnalysisResult {
        return SerializableAnalysisResult(
            originalUrl = r.originalUrl,
            finalUrl = r.finalUrl,
            riskScore = r.riskScore,
            verdict = r.verdict.name,
            reasons = r.reasons.map { "${it.code}|${it.severity.name}|${it.messagePt}" },
            impersonatedBrand = r.impersonatedBrand,
            officialDomain = r.officialDomain,
            hasHomograph = r.hasHomograph
        )
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        val data = intent?.data
        if (intent?.action == Intent.ACTION_VIEW && data != null) {
            handleLink(data.toString())
        } else {
            finish()
            overridePendingTransition(0, 0)
        }
    }
}
