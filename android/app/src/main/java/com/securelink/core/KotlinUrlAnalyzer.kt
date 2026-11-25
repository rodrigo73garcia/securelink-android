package com.securelink.core

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.util.Locale

/**
 * Motor de análise de URLs 100% em Kotlin (fallback quando lib nativa não está disponível).
 * Implementa: homógrafos IDN, typosquatting, heurísticas de URL, blocklist local, marcas BR.
 */
object KotlinUrlAnalyzer {

    private const val TAG = "KotlinUrlAnalyzer"

    private var brands: List<BrandEntry> = emptyList()
    private var blocklist: Set<String> = emptySet()
    private var suspiciousTlds: Set<String> = emptySet()
    private var phishingKeywords: Set<String> = emptySet()

    data class BrandEntry(
        val name: String,
        val officialDomain: String,
        val keywords: List<String>
    )

    data class Result(
        val riskScore: Int,
        val verdict: Verdict,
        val reasons: List<Reason>,
        val impersonatedBrand: String?,
        val hasHomograph: Boolean,
        val domainAgeDays: Int?
    )

    fun init(context: Context) {
        try {
            // Carrega marcas brasileiras
            val brandsJson = context.assets.open("brands/br.json").bufferedReader().use { it.readText() }
            val brandsArray = JSONArray(brandsJson)
            brands = (0 until brandsArray.length()).map { i ->
                val b = brandsArray.getJSONObject(i)
                BrandEntry(
                    name = b.getString("name"),
                    officialDomain = b.getString("official_domain"),
                    keywords = (0 until b.getJSONArray("keywords").length()).map { b.getJSONArray("keywords").getString(it) }
                )
            }

            // Carrega TLDs suspeitos
            val tldsJson = context.assets.open("config/suspicious_tlds.json").bufferedReader().use { it.readText() }
            val tldsArray = JSONArray(tldsJson)
            suspiciousTlds = (0 until tldsArray.length()).map { tldsArray.getString(it) }.toSet()

            // Carrega keywords de phishing
            val kwJson = context.assets.open("config/phishing_keywords.json").bufferedReader().use { it.readText() }
            val kwArray = JSONArray(kwJson)
            phishingKeywords = (0 until kwArray.length()).map { kwArray.getString(it).lowercase() }.toSet()

            Log.d(TAG, "Inicializado: ${brands.size} marcas, ${suspiciousTlds.size} TLDs, ${phishingKeywords.size} keywords")
        } catch (e: Exception) {
            Log.e(TAG, "Erro ao carregar assets: ${e.message}")
        }
    }

    fun loadBlocklist(domains: Set<String>) {
        blocklist = domains
        Log.d(TAG, "Blocklist carregada: ${domains.size} domínios")
    }

    fun analyze(url: String): Result {
        val reasons = mutableListOf<Reason>()
        var riskScore = 0
        var impersonatedBrand: String? = null
        var hasHomograph = false

        try {
            val uri = URI(url)
            val host = uri.host?.lowercase() ?: return Result(100, Verdict.BLOCKED, listOf(Reason("invalid_url", "URL inválida", Severity.CRITICAL)), null, false, null)

            val domain = extractBaseDomain(host)
            val sld = host.split(".")[0]

            // 1. Verifica blocklist
            if (isInBlocklist(domain) || isInBlocklist(host)) {
                riskScore += 50
                reasons.add(Reason("blocklist", "Domínio presente em lista de phishing conhecida", Severity.CRITICAL))
            }

            // 2. Homógrafos / IDN
            val homographResult = checkHomograph(host)
            if (homographResult != null) {
                hasHomograph = true
                riskScore += 40
                reasons.add(Reason("homograph", homographResult, Severity.CRITICAL))
            }

            // 3. Typosquatting contra marcas
            val typoResult = checkTyposquatting(sld, domain, host)
            if (typoResult != null) {
                riskScore += 35
                impersonatedBrand = typoResult.first
                reasons.add(Reason("typosquatting", typoResult.second, Severity.CRITICAL))
            }

            // 4. TLD suspeito
            val tld = host.substringAfterLast('.')
            if (suspiciousTlds.contains(tld)) {
                riskScore += 15
                reasons.add(Reason("suspicious_tld", "Extensão de domínio frequentemente usada em golpes (.$tld)", Severity.WARNING))
            }

            // 5. Keywords de phishing na URL
            val urlLower = url.lowercase()
            val foundKeywords = phishingKeywords.filter { urlLower.contains(it) }
            if (foundKeywords.isNotEmpty()) {
                riskScore += 20
                reasons.add(Reason("phishing_keywords", "Contém termos comuns em golpes: ${foundKeywords.take(3).joinToString(", ")}", Severity.WARNING))
            }

            // 6. IP como hostname
            if (host.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))) {
                riskScore += 30
                reasons.add(Reason("ip_host", "Usa endereço IP direto em vez de nome de domínio", Severity.WARNING))
            }

            // 7. Muitos subdomínios
            val subdomainCount = host.split(".").size - 2
            if (subdomainCount > 3) {
                riskScore += 10
                reasons.add(Reason("many_subdomains", "Muitos subdomínios aninhados ($subdomainCount níveis)", Severity.INFO))
            }

            // 8. URL muito longa
            if (url.length > 100) {
                riskScore += 5
                reasons.add(Reason("long_url", "URL muito longa (${url.length} caracteres)", Severity.INFO))
            }

            // 9. @ na URL (ofuscação)
            if (url.contains("@")) {
                riskScore += 25
                reasons.add(Reason("at_symbol", "Contém '@' que pode enganar sobre o destino real", Severity.WARNING))
            }

        } catch (e: Exception) {
            Log.e(TAG, "Erro na análise: ${e.message}")
            riskScore += 50
            reasons.add(Reason("parse_error", "Não foi possível analisar a URL", Severity.WARNING))
        }

        riskScore = riskScore.coerceIn(0, 100)
        val verdict = when {
            riskScore >= 70 -> Verdict.BLOCKED
            riskScore >= 30 -> Verdict.SUSPICIOUS
            else -> Verdict.SAFE
        }

        if (verdict == Verdict.SAFE && reasons.isEmpty()) {
            reasons.add(Reason("ok", "Nenhum sinal de golpe detectado", Severity.INFO))
        }

        return Result(riskScore, verdict, reasons, impersonatedBrand, hasHomograph, null)
    }

    private fun isInBlocklist(domain: String): Boolean {
        if (blocklist.isEmpty()) return false
        var d = domain
        while (d.contains(".")) {
            if (blocklist.contains(d)) return true
            d = d.substringAfter(".")
        }
        return blocklist.contains(d)
    }

    private fun checkHomograph(host: String): String? {
        // Verifica punycode
        if (host.contains("xn--")) {
            return "Domínio usa codificação internacional (Punycode) - pode conter caracteres de outros alfabetos"
        }

        // Verifica caracteres não-ASCII (cirílico, grego, etc.)
        val nonAscii = host.filter { it.code > 127 }
        if (nonAscii.isNotEmpty()) {
            val scripts = mutableSetOf<String>()
            nonAscii.forEach { c ->
                when {
                    c.code in 0x0400..0x04FF -> scripts.add("cirílico")
                    c.code in 0x0370..0x03FF -> scripts.add("grego")
                    c.code in 0x0600..0x06FF -> scripts.add("árabe")
                    c.code in 0x0900..0x097F -> scripts.add("devanagari")
                    else -> scripts.add("outro")
                }
            }
            return "Hostname contém caracteres não-Latinos (${scripts.joinToString(", ")}): '${nonAscii.take(5).joinToString("")}' - comum em golpes de homógrafo"
        }

        // Verifica混合 scripts (latino + não-latino no mesmo domínio)
        val hasLatin = host.any { it.code in 0x41..0x5A || it.code in 0x61..0x7A }
        if (hasLatin && nonAscii.isNotEmpty()) {
            return "Mistura de alfabetos Latino e não-Latino no domínio"
        }

        return null
    }

    private fun checkTyposquatting(sld: String, domain: String, fullHost: String): Pair<String, String>? {
        for (brand in brands) {
            val brandSld = brand.officialDomain.split(".")[0]

            // Distância de Levenshtein simples
            val dist = levenshtein(sld.lowercase(), brandSld.lowercase())
            if (dist in 1..2 && sld.length > 3) {
                return Pair(brand.name, "Domínio '$sld' é muito parecido com '${brand.officialDomain}' (distância $dist) - possível golpe imitando ${brand.name}")
            }

            // Combosquatting: marca + palavra extra
            for (kw in brand.keywords) {
                if (sld.lowercase().contains(kw.lowercase()) && !domain.equals(brand.officialDomain, ignoreCase = true) && !sld.equals(brandSld, ignoreCase = true)) {
                    // Verifica se não é o domínio oficial
                    if (!fullHost.endsWith(brand.officialDomain, ignoreCase = true)) {
                        return Pair(brand.name, "Domínio contém a marca '${brand.name}' mas não é o site oficial (${brand.officialDomain})")
                    }
                }
            }

            // Subdomain trick: marca.com.br.evil.com
            if (fullHost.startsWith(brand.officialDomain + ".", ignoreCase = true) || fullHost.contains("." + brand.officialDomain + ".")) {
                return Pair(brand.name, "Marca '${brand.name}' aparece como subdomínio de outro site - golpe comum")
            }
        }
        return null
    }

    private fun levenshtein(a: String, b: String): Int {
        val dp = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) dp[i][0] = i
        for (j in 0..b.length) dp[0][j] = j
        for (i in 1..a.length) {
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                dp[i][j] = minOf(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
            }
        }
        return dp[a.length][b.length]
    }

    private fun extractBaseDomain(host: String): String {
        val parts = host.split(".")
        if (parts.size <= 2) return host
        // Trata .com.br, .org.br, etc.
        val brTwoLevel = setOf("com", "org", "net", "gov", "edu", "mil", "art", "blog", "eco", "emp", "etc", "inf", "JOR", "jus", "leg", "med", "mus", "nom", "ntr", "odo", "ppg", "pro", "psc", "psi", "slg", "adm", "adv", "arq", "ato", "bio", "bmd", "cim", "cng", "cnt", "coop", "ecn", "eng", "esp", "etc", "eti", "far", "flog", "fm", "fnd", "fot", "fst", "g12", "ggf", "imb", "ind", "jus", "leil", "mat", "mp", "net", "not", "ntr", "odo", "ppg", "pro", "psc", "psi", "qsl", "radio", "rec", "slg", "srv", "taxi", "teo", "tmp", "trd", "tur", "tv", "vet", "vlog", "wiki", "zlg")
        return if (parts.size >= 3 && parts[parts.size - 2] == "br" && brTwoLevel.contains(parts[parts.size - 3].lowercase())) {
            parts.takeLast(3).joinToString(".")
        } else {
            parts.takeLast(2).joinToString(".")
        }
    }
}
