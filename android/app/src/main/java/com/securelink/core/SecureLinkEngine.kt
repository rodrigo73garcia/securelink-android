package com.securelink.core

import android.util.Log

/**
 * Bridge JNI para o motor Rust nativo.
 * Todas as chamadas são delegadas para libsecurelink_core.so
 */
object SecureLinkEngine {
    
    private const val TAG = "SecureLinkEngine"
    
    // Carrega a biblioteca nativa
    init {
        try {
            System.loadLibrary("securelink_core")
            Log.d(TAG, "Biblioteca nativa libsecurelink_core.so carregada")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Falha ao carregar biblioteca nativa: ${e.message}")
        }
    }

    /**
     * Inicializa o motor com configuração JSON
     * @param configJson JSON com EngineConfig
     * @return true se sucesso
     */
    @JvmStatic
    external fun init(configJson: String): Boolean

    /**
     * Carrega Bloom filter de arquivo
     * @param path Caminho absoluto do arquivo .bloom
     * @return true se sucesso
     */
    @JvmStatic
    external fun loadBloomFilter(path: String): Boolean

    /**
     * Análise completa de URL - retorna JSON com FfiAnalysisResult
     * @param url URL para analisar
     * @return JSON string com resultado completo
     */
    @JvmStatic
    external fun analyzeUrl(url: String): String

    /**
     * Verificação rápida - retorna apenas score de risco (0-100)
     * @param url URL para verificar
     * @return Score de risco (0-100), 50 se engine não inicializado
     */
    @JvmStatic
    external fun quickCheck(url: String): Int

    /**
     * Verifica se domínio está na blocklist offline
     * @param domain Domínio para verificar
     * @return true se bloqueado
     */
    @JvmStatic
    external fun isBlocklisted(domain: String): Boolean

    /**
     * Obtém idade do domínio em dias via RDAP
     * @param domain Domínio para consultar
     * @return Idade em dias, 0 se falhou/indisponível
     */
    @JvmStatic
    external fun getDomainAge(domain: String): Int

    /**
     * Expande URL curta (bit.ly, t.co, etc.)
     * @param url URL possivelmente curta
     * @return URL final expandida, ou original se falhou
     */
    @JvmStatic
    external fun expandUrl(url: String): String

    /**
     * Verifica se a engine está disponível
     */
    fun isAvailable(): Boolean {
        // Tenta uma chamada simples
        return try {
            quickCheck("https://example.com") != 50 || true // Se chegou aqui, JNI funciona
        } catch (e: Exception) {
            false
        }
    }
}

/**
 * Modelos de dados para resultado da análise (lado Kotlin)
 */
data class AnalysisResult(
    val originalUrl: String,
    val finalUrl: String,
    val domain: String,
    val punycodeDomain: String?,
    val riskScore: Int,
    val verdict: Verdict,
    val reasons: List<Reason>,
    val impersonatedBrand: String?,
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

/**
 * Converte JSON do Rust para objetos Kotlin
 */
object AnalysisResultParser {
    private val gson = com.google.gson.Gson()
    
    fun parse(json: String): AnalysisResult {
        val ffiResult = gson.fromJson(json, FfiAnalysisResult::class.java)
        return AnalysisResult(
            originalUrl = ffiResult.finalUrl, // Será preenchido pelo chamador
            finalUrl = ffiResult.finalUrl,
            domain = "", // Extraído separadamente
            punycodeDomain = null,
            riskScore = ffiResult.riskScore,
            verdict = when (ffiResult.verdict) {
                "Safe" -> Verdict.SAFE
                "Suspicious" -> Verdict.SUSPICIOUS
                "Blocked" -> Verdict.BLOCKED
                else -> Verdict.SUSPICIOUS
            },
            reasons = ffiResult.reasons.map { Reason(it.code, it.messagePt, when(it.severity) {
                "Info" -> Severity.INFO
                "Warning" -> Severity.WARNING
                "Critical" -> Severity.CRITICAL
                else -> Severity.WARNING
            }) },
            impersonatedBrand = ffiResult.impersonatedBrand,
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