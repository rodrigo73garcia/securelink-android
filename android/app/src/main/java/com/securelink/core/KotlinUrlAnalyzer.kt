package com.securelink.core

import android.content.Context
import android.util.Log
import org.json.JSONArray
import java.net.IDN
import java.net.URI

/**
 * Motor de análise de URLs 100% em Kotlin.
 * Implementa: homógrafos IDN, typosquatting, combosquatting, blocklist local e 96 marcas BR.
 */
object KotlinUrlAnalyzer {

    private const val TAG = "KotlinUrlAnalyzer"

    @Volatile
    private var initialized = false
    private var brands: List<BrandEntry> = emptyList()
    private var blocklist: Set<String> = emptySet()
    private var suspiciousTlds: Set<String> = emptySet()
    private var phishingKeywords: Set<String> = emptySet()

    private val SUFFIXES_TO_STRIP = listOf(
        "oficial", "official", "promo", "promocao", "oferta", "ofertas",
        "loja", "shop", "store", "online", "seguro", "segura", "sac",
        "atendimento", "suporte", "cliente", "clientes", "verifica",
        "verificacao", "login", "acesso", "cadastro", "atualiza",
        "atualizacao", "digital", "pay", "app", "club", "vip", "br"
    )

    private val TRUSTED_COMMON_DOMAINS = setOf(
        "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
        "wikipedia.org", "wikimedia.org", "globo.com", "g1.globo.com",
        "uol.com.br", "folha.uol.com.br", "terra.com.br", "estadao.com.br",
        "r7.com", "ig.com.br", "cnnbrasil.com.br", "bbc.com",
        "linkedin.com", "x.com", "twitter.com", "tiktok.com", "reddit.com",
        "twitch.tv", "discord.com", "discord.gg", "stackoverflow.com",
        "mozilla.org", "firefox.com", "duckduckgo.com", "brave.com",
        "mercadopago.com.br", "mercadopago.com", "shopee.com.br",
        "aliexpress.com", "shein.com", "booking.com", "airbnb.com.br",
        "airbnb.com", "gov.br"
    )

    data class BrandEntry(
        val name: String,
        val officialDomain: String,
        val altDomains: List<String>,
        val keywords: List<String>
    )

    data class Result(
        val riskScore: Int,
        val verdict: Verdict,
        val reasons: List<Reason>,
        val impersonatedBrand: String?,
        val officialDomain: String?,
        val hasHomograph: Boolean,
        val domainAgeDays: Int?
    )

    @Synchronized
    fun init(context: Context) {
        if (initialized) return
        try {
            val brandsJson = context.assets.open("brands/br.json").bufferedReader().use { it.readText() }
            val brandsArray = JSONArray(brandsJson)
            brands = (0 until brandsArray.length()).map { i ->
                val b = brandsArray.getJSONObject(i)
                val altArr = b.optJSONArray("alt_domains")
                val alts = if (altArr != null) {
                    (0 until altArr.length()).map { altArr.getString(it).lowercase() }
                } else {
                    emptyList()
                }
                val kwArr = b.optJSONArray("keywords")
                val kws = if (kwArr != null) {
                    (0 until kwArr.length()).map { kwArr.getString(it) }
                } else {
                    emptyList()
                }
                BrandEntry(
                    name = b.getString("name"),
                    officialDomain = b.getString("official_domain").lowercase(),
                    altDomains = alts,
                    keywords = kws
                )
            }

            val tldsJson = context.assets.open("config/suspicious_tlds.json").bufferedReader().use { it.readText() }
            val tldsArray = JSONArray(tldsJson)
            suspiciousTlds = (0 until tldsArray.length()).map { tldsArray.getString(it).lowercase() }.toSet()

            val kwJson = context.assets.open("config/phishing_keywords.json").bufferedReader().use { it.readText() }
            val kwArray = JSONArray(kwJson)
            phishingKeywords = (0 until kwArray.length()).map { kwArray.getString(it).lowercase() }.toSet()

            // Carrega blocklist em cache local se existir
            val cachedBlocklist = context.filesDir.resolve("blocklist.txt")
            if (cachedBlocklist.exists()) {
                val lines = cachedBlocklist.readLines()
                    .map { it.trim().lowercase() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .toSet()
                if (lines.isNotEmpty()) {
                    blocklist = lines
                }
            }

            initialized = true
            Log.d(TAG, "Inicializado: ${brands.size} marcas, ${suspiciousTlds.size} TLDs, ${blocklist.size} bloqueados")
        } catch (e: Exception) {
            Log.e(TAG, "Erro ao carregar assets: ${e.message}")
        }
    }

    fun loadBlocklist(domains: Set<String>) {
        blocklist = domains
        Log.d(TAG, "Blocklist carregada: ${domains.size} domínios")
    }

    fun analyze(rawUrl: String): Result {
        val url = BrowserHelper.normalizeUrl(rawUrl)
        val reasons = mutableListOf<Reason>()
        var riskScore = 0
        var impersonatedBrand: String? = null
        var officialDomain: String? = null
        var hasHomograph = false

        try {
            val uri = URI(url)
            val rawHost = uri.host?.lowercase()?.removePrefix("www.") ?: run {
                // Tenta converter IDN unicode para checar host
                val manualHost = url.substringAfter("://").substringBefore("/").substringBefore("?").substringBefore("#").substringBefore(":").lowercase().removePrefix("www.")
                if (manualHost.isBlank()) {
                    return Result(100, Verdict.BLOCKED, listOf(Reason("invalid_url", "URL inválida ou malformada", Severity.CRITICAL)), null, null, false, null)
                }
                manualHost
            }

            val host = rawHost
            val unicodeHost = try {
                IDN.toUnicode(host)
            } catch (_: Exception) {
                host
            }

            val domain = extractBaseDomain(host)
            val sld = domain.substringBefore(".")

            // 1. Verifica homógrafos / IDN (checa tanto o host bruto quanto o decodificado)
            val homographResult = checkHomograph(host, unicodeHost)
            if (homographResult != null) {
                hasHomograph = true
                riskScore += 60
                reasons.add(Reason("homograph", homographResult, Severity.CRITICAL))
            }

            // 2. Verifica blocklist local
            if (isInBlocklist(domain) || isInBlocklist(host)) {
                riskScore += 75
                reasons.add(Reason("blocklist", "Domínio presente em lista de phishing conhecida", Severity.CRITICAL))
            }

            // 3. Se NÃO tem homógrafo nem está em blocklist e é domínio oficial conhecido -> SAFE imediato
            if (!hasHomograph && riskScore == 0 && isKnownOfficialDomain(host, domain)) {
                return Result(
                    riskScore = 0,
                    verdict = Verdict.SAFE,
                    reasons = listOf(Reason("official_domain", "Site oficial verificado", Severity.INFO)),
                    impersonatedBrand = null,
                    officialDomain = null,
                    hasHomograph = false,
                    domainAgeDays = null
                )
            }

            // 4. Typosquatting / combosquatting contra marcas brasileiras e globais
            val typoResult = checkTyposquatting(sld, domain, host)
            if (typoResult != null) {
                riskScore += 55
                impersonatedBrand = typoResult.brandName
                officialDomain = typoResult.officialDomain
                reasons.add(Reason("typosquatting", typoResult.message, Severity.CRITICAL))
            }

            // 5. TLD suspeito
            val tld = host.substringAfterLast('.')
            if (suspiciousTlds.contains(tld)) {
                riskScore += 20
                reasons.add(Reason("suspicious_tld", "Extensão de domínio frequentemente usada em golpes (.$tld)", Severity.WARNING))
            }

            // 6. IP direto como hostname
            if (host.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))) {
                riskScore += 45
                reasons.add(Reason("ip_host", "Usa endereço IP direto em vez de nome de domínio", Severity.WARNING))
            }

            // 7. @ na URL (técnica de ofuscação de destino)
            if (url.substringBefore("?").contains("@")) {
                riskScore += 40
                reasons.add(Reason("at_symbol", "Contém '@' que pode enganar sobre o destino real", Severity.CRITICAL))
            }

            // 8. Keywords de phishing apenas no host/subdomínio ou combinadas no path
            val hostMatches = phishingKeywords.filter { kw ->
                kw.length >= 4 && host.contains(kw)
            }
            if (hostMatches.isNotEmpty()) {
                riskScore += 20
                reasons.add(
                    Reason(
                        "phishing_keywords",
                        "Domínio contém termos comuns em golpes: ${hostMatches.take(3).joinToString(", ")}",
                        Severity.WARNING
                    )
                )
            }

            // 9. Muitos subdomínios aninhados
            val subdomainCount = host.split(".").size - 2
            if (subdomainCount > 3) {
                riskScore += 15
                reasons.add(Reason("many_subdomains", "Muitos subdomínios aninhados ($subdomainCount níveis)", Severity.INFO))
            }

            // 10. URL extremamente longa
            if (url.length > 220) {
                riskScore += 5
                reasons.add(Reason("long_url", "URL muito longa (${url.length} caracteres)", Severity.INFO))
            }

        } catch (e: Exception) {
            Log.e(TAG, "Erro na análise de '$url': ${e.message}")
            riskScore += 40
            reasons.add(Reason("parse_error", "Não foi possível validar o formato da URL", Severity.WARNING))
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

        return Result(riskScore, verdict, reasons, impersonatedBrand, officialDomain, hasHomograph, null)
    }

    private fun isKnownOfficialDomain(host: String, baseDomain: String): Boolean {
        if (TRUSTED_COMMON_DOMAINS.any { trusted ->
                host == trusted || host.endsWith(".$trusted") || baseDomain == trusted
            }
        ) {
            return true
        }

        for (brand in brands) {
            if (host == brand.officialDomain || host.endsWith(".${brand.officialDomain}") || baseDomain == brand.officialDomain) {
                return true
            }
            if (brand.altDomains.any { alt ->
                    host == alt || host.endsWith(".$alt") || baseDomain == alt
                }
            ) {
                return true
            }
        }
        return false
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

    private fun checkHomograph(host: String, unicodeHost: String): String? {
        if (host.contains("xn--")) {
            return "Domínio usa codificação internacional Punycode ($unicodeHost) — técnica clássica para falsificar endereços reais"
        }

        val nonAscii = unicodeHost.filter { it.code > 127 }
        if (nonAscii.isNotEmpty()) {
            val scripts = mutableSetOf<String>()
            nonAscii.forEach { c ->
                when (c.code) {
                    in 0x0400..0x04FF -> scripts.add("cirílico")
                    in 0x0370..0x03FF -> scripts.add("grego")
                    in 0x0600..0x06FF -> scripts.add("árabe")
                    in 0x0900..0x097F -> scripts.add("devanagari")
                    else -> scripts.add("não-latino")
                }
            }
            return "Endereço contém caracteres falsos (${scripts.joinToString(", ")}): '${nonAscii.take(5)}' — golpe de homógrafo"
        }

        return null
    }

    private data class TypoMatch(
        val brandName: String,
        val officialDomain: String,
        val message: String
    )

    private fun checkTyposquatting(sld: String, domain: String, fullHost: String): TypoMatch? {
        val cleanSld = sld.lowercase().replace("-", "")
        val deLeetSld = normalizeLeet(cleanSld)
        val strippedSld = stripSuspiciousSuffixes(deLeetSld)

        for (brand in brands) {
            // Pula se for o próprio domínio oficial ou alternativo da marca
            if (fullHost == brand.officialDomain ||
                fullHost.endsWith(".${brand.officialDomain}") ||
                brand.altDomains.any { fullHost == it || fullHost.endsWith(".$it") }
            ) {
                continue
            }

            // Subdomain trick: marca.com.br.sitefalso.com
            if (fullHost.startsWith("${brand.officialDomain}.") || fullHost.contains(".${brand.officialDomain}.")) {
                return TypoMatch(
                    brand.name,
                    brand.officialDomain,
                    "Usa '${brand.officialDomain}' como subdomínio de outro site — golpe comum"
                )
            }

            // Gera tokens representativos da marca (SLD oficial + nome normalizado da marca)
            val brandSld = brand.officialDomain.substringBefore(".").lowercase().replace("-", "")
            val brandSlug = brand.name.lowercase()
                .replace(Regex("[^a-z0-9]"), "")

            val brandTokens = listOf(brandSld, brandSlug)
                .filter { it.length >= 4 }
                .distinct()

            for (token in brandTokens) {
                // 1. Combosquatting exato: domínio contém o nome inteiro da marca (ex: nubank-seguro.com)
                if (cleanSld.contains(token) && cleanSld != token) {
                    return TypoMatch(
                        brand.name,
                        brand.officialDomain,
                        "Domínio '$domain' usa o nome '${brand.name}', mas não é o site oficial (${brand.officialDomain})"
                    )
                }

                // 2. Leet-speak ou sufixos extras: cacaoshowbr -> cacaoshow -> parecido com cacaushow
                if (deLeetSld == token && cleanSld != token) {
                    return TypoMatch(
                        brand.name,
                        brand.officialDomain,
                        "Domínio '$domain' substitui letras por números/símbolos para imitar ${brand.name} (${brand.officialDomain})"
                    )
                }

                // 3. Levenshtein direto e com sufixos removidos (ex: cacaoshowbr -> cacaoshow)
                val maxDist = if (token.length <= 5) 1 else 2
                val distDirect = levenshtein(deLeetSld, token)
                val distStripped = if (strippedSld != deLeetSld && strippedSld.length >= 4) {
                    levenshtein(strippedSld, token)
                } else {
                    Int.MAX_VALUE
                }

                if (distDirect in 1..maxDist || distStripped in 0..maxDist) {
                    return TypoMatch(
                        brand.name,
                        brand.officialDomain,
                        "Domínio '$domain' é visualmente muito parecido com '${brand.officialDomain}' — possível golpe imitando ${brand.name}"
                    )
                }
            }
        }
        return null
    }

    private fun stripSuspiciousSuffixes(sld: String): String {
        var current = sld
        var changed = true
        while (changed && current.length > 4) {
            changed = false
            for (suffix in SUFFIXES_TO_STRIP) {
                if (current.endsWith(suffix) && current.length - suffix.length >= 4) {
                    current = current.removeSuffix(suffix)
                    changed = true
                    break
                }
                if (current.startsWith(suffix) && current.length - suffix.length >= 4) {
                    current = current.removePrefix(suffix)
                    changed = true
                    break
                }
            }
        }
        return current
    }

    private fun normalizeLeet(input: String): String {
        return input
            .replace('0', 'o')
            .replace('1', 'l')
            .replace('3', 'e')
            .replace('4', 'a')
            .replace('5', 's')
            .replace('7', 't')
            .replace("rn", "m")
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
        val parts = host.split(".").filter { it.isNotEmpty() }
        if (parts.size <= 2) return host
        val brTwoLevel = setOf(
            "com", "org", "net", "gov", "edu", "mil", "art", "blog", "eco", "emp",
            "etc", "inf", "jus", "leg", "med", "mus", "nom", "pro", "tur", "tv"
        )
        return if (parts.size >= 3 && parts[parts.size - 2] == "br" && brTwoLevel.contains(parts[parts.size - 3])) {
            parts.takeLast(3).joinToString(".")
        } else {
            parts.takeLast(2).joinToString(".")
        }
    }
}
