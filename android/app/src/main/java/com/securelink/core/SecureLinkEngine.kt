package com.securelink.core

import android.content.Context
import android.util.Log

/**
 * Bridge unificado: usa motor Rust nativo (JNI) se disponível,
 * senão usa o motor Kotlin puro (KotlinUrlAnalyzer).
 */
object SecureLinkEngine {

    private const val TAG = "SecureLinkEngine"
    private var nativeAvailable = false
    private var appContext: Context? = null

    init {
        try {
            System.loadLibrary("securelink_core")
            nativeAvailable = true
            Log.d(TAG, "Motor nativo Rust carregado")
        } catch (_: UnsatisfiedLinkError) {
            nativeAvailable = false
            Log.d(TAG, "Usando motor Kotlin puro")
        }
    }

    fun init(context: Context) {
        this.appContext = context.applicationContext
        if (!nativeAvailable) {
            KotlinUrlAnalyzer.init(context.applicationContext)
        }
    }

    fun ensureInitialized(context: Context) {
        if (appContext == null) {
            init(context)
        } else if (!nativeAvailable) {
            KotlinUrlAnalyzer.init(context.applicationContext)
        }
    }

    /**
     * Analisa URL e retorna resultado unificado.
     */
    fun analyze(url: String): AnalysisResult {
        return if (nativeAvailable) {
            try {
                val json = analyzeUrlNative(url)
                AnalysisResultParser.parse(json).copy(originalUrl = url)
            } catch (e: Exception) {
                Log.e(TAG, "Erro no motor nativo, usando Kotlin: ${e.message}")
                analyzeKotlin(url)
            }
        } else {
            analyzeKotlin(url)
        }
    }

    private fun analyzeKotlin(url: String): AnalysisResult {
        val r = KotlinUrlAnalyzer.analyze(url)
        return AnalysisResult(
            originalUrl = url,
            finalUrl = BrowserHelper.normalizeUrl(url),
            domain = url.substringAfter("://").substringBefore("/").substringBefore(":"),
            punycodeDomain = null,
            riskScore = r.riskScore,
            verdict = r.verdict,
            reasons = r.reasons,
            impersonatedBrand = r.impersonatedBrand,
            officialDomain = r.officialDomain,
            domainAgeDays = r.domainAgeDays,
            hasHomograph = r.hasHomograph,
            inBlocklist = r.reasons.any { it.code == "blocklist" },
            analyzedAtMs = System.currentTimeMillis()
        )
    }

    fun quickCheck(url: String): Int = analyze(url).riskScore

    fun isBlocklisted(domain: String): Boolean {
        return if (nativeAvailable) {
            try { isBlocklistedNative(domain) } catch (_: Exception) { false }
        } else {
            KotlinUrlAnalyzer.analyze("https://$domain").reasons.any { it.code == "blocklist" }
        }
    }

    fun loadBlocklist(domains: Set<String>) {
        if (!nativeAvailable) {
            KotlinUrlAnalyzer.loadBlocklist(domains)
        }
    }

    fun isNativeAvailable(): Boolean = nativeAvailable

    private external fun analyzeUrlNative(url: String): String
    private external fun isBlocklistedNative(domain: String): Boolean
}

data class AnalysisResult(
    val originalUrl: String,
    val finalUrl: String,
    val domain: String,
    val punycodeDomain: String?,
    val riskScore: Int,
    val verdict: Verdict,
    val reasons: List<Reason>,
    val impersonatedBrand: String?,
    val officialDomain: String?,
    val domainAgeDays: Int?,
    val hasHomograph: Boolean,
    val inBlocklist: Boolean,
    val analyzedAtMs: Long
)

enum class Verdict {
    SAFE, SUSPICIOUS, BLOCKED
}

data class Reason(
    val code: String,
    val messagePt: String,
    val severity: Severity
)

enum class Severity {
    INFO, WARNING, CRITICAL
}

object AnalysisResultParser {
    private val gson = com.google.gson.Gson()

    fun parse(json: String): AnalysisResult {
        val ffiResult = gson.fromJson(json, FfiAnalysisResult::class.java)
        return AnalysisResult(
            originalUrl = ffiResult.finalUrl,
            finalUrl = ffiResult.finalUrl,
            domain = "",
            punycodeDomain = null,
            riskScore = ffiResult.riskScore,
            verdict = when (ffiResult.verdict) {
                "Safe" -> Verdict.SAFE
                "Suspicious" -> Verdict.SUSPICIOUS
                "Blocked" -> Verdict.BLOCKED
                else -> Verdict.SUSPICIOUS
            },
            reasons = ffiResult.reasons.map {
                Reason(
                    it.code,
                    it.messagePt,
                    when (it.severity) {
                        "Info" -> Severity.INFO
                        "Warning" -> Severity.WARNING
                        "Critical" -> Severity.CRITICAL
                        else -> Severity.WARNING
                    }
                )
            },
            impersonatedBrand = ffiResult.impersonatedBrand,
            officialDomain = null,
            domainAgeDays = ffiResult.domainAgeDays,
            hasHomograph = ffiResult.hasHomograph,
            inBlocklist = ffiResult.inBlocklist,
            analyzedAtMs = System.currentTimeMillis()
        )
    }

    private data class FfiAnalysisResult(
        val finalUrl: String,
        val riskScore: Int,
        val verdict: String,
        val reasons: List<FfiReason>,
        val impersonatedBrand: String?,
        val domainAgeDays: Int?,
        val hasHomograph: Boolean,
        val inBlocklist: Boolean
    )

    private data class FfiReason(
        val code: String,
        val messagePt: String,
        val severity: String
    )
}
