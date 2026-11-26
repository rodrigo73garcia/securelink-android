package com.securelink.core

import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Log

/**
 * Gerencia a detecção do navegador original do usuário,
 * solicitação de navegador padrão para o SecureLink,
 * e o redirecionamento final dos links para o navegador real.
 */
object BrowserHelper {

    private const val TAG = "BrowserHelper"
    private const val PREFS_NAME = "securelink_prefs"
    private const val KEY_TARGET_BROWSER_PKG = "target_browser_package"
    private const val KEY_TARGET_BROWSER_NAME = "target_browser_name"
    private const val KEY_PROMPTED_ONCE = "default_prompted_once"
    private const val KEY_STATS_CHECKED = "stats_links_checked"
    private const val KEY_STATS_BLOCKED = "stats_links_blocked"
    private const val KEY_USER_DECLINED = "user_declined_reprompt"
    private const val KEY_DECLINED_TS = "declined_ts"
    private const val KEY_LAST_REPROMPT_TS = "last_reprompt_ts"

    private val PREFERRED_BROWSER_PACKAGES = listOf(
        "org.mozilla.firefox",
        "com.android.chrome",
        "com.brave.browser",
        "com.sec.android.app.sbrowser",
        "com.microsoft.emmx",
        "com.opera.browser",
        "com.opera.mini.native",
        "com.duckduckgo.mobile.android",
        "com.vivaldi.browser",
        "org.mozilla.focus",
        "com.kiwibrowser.browser",
        "com.UCMobile.intl",
        "com.android.browser"
    )

    data class BrowserInfo(
        val packageName: String,
        val label: String
    )

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Verifica se o SecureLink já está configurado como navegador padrão no Android.
     */
    fun isSecureLinkDefaultBrowser(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = context.getSystemService(RoleManager::class.java)
            if (roleManager != null && roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER)) {
                return roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)
            }
        }
        val testIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"))
        val resolveInfo = resolveDefaultActivity(context.packageManager, testIntent)
        return resolveInfo?.activityInfo?.packageName == context.packageName
    }

    /**
     * Cria o Intent para pedir ao usuário com 1 toque para definir o SecureLink como navegador padrão.
     * No Android 10+ abre o diálogo nativo de RoleManager; em versões anteriores abre Apps Padrão.
     */
    fun createRequestDefaultBrowserIntent(context: Context): Intent {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = context.getSystemService(RoleManager::class.java)
            if (roleManager != null && roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER)) {
                return roleManager.createRequestRoleIntent(RoleManager.ROLE_BROWSER)
            }
        }
        return Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)
    }

    /**
     * Detecta qual navegador está atualmente como padrão ANTES do SecureLink assumir,
     * e salva nas configurações internas do app.
     * Se não houver um padrão definido (ou se já for o próprio SecureLink e ainda não tiver salvo),
     * seleciona automaticamente o navegador preferido instalado.
     */
    fun detectAndSavePreviousDefaultBrowser(context: Context): BrowserInfo? {
        val currentSaved = getSavedTargetBrowser(context)
        val pm = context.packageManager
        val installed = getInstalledBrowsers(context)

        // 1. Tenta descobrir qual é o navegador padrão atual do sistema
        val testIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        val resolved = resolveDefaultActivity(pm, testIntent)
        val resolvedPkg = resolved?.activityInfo?.packageName

        if (resolvedPkg != null &&
            resolvedPkg != context.packageName &&
            resolvedPkg != "android" &&
            installed.any { it.packageName == resolvedPkg }
        ) {
            val label = installed.first { it.packageName == resolvedPkg }.label
            saveTargetBrowser(context, resolvedPkg, label)
            Log.d(TAG, "Navegador padrão anterior detectado e salvo: $label ($resolvedPkg)")
            return BrowserInfo(resolvedPkg, label)
        }

        // 2. Se já tinha um navegador válido salvo e ainda está instalado, mantém
        if (currentSaved != null && installed.any { it.packageName == currentSaved.packageName }) {
            return currentSaved
        }

        // 3. Fallback: escolhe o primeiro navegador real da lista de preferência
        val preferred = pickPreferredBrowser(installed)
        if (preferred != null) {
            saveTargetBrowser(context, preferred.packageName, preferred.label)
            Log.d(TAG, "Navegador padrão selecionado via fallback: ${preferred.label} (${preferred.packageName})")
            return preferred
        }

        return null
    }

    fun saveTargetBrowser(context: Context, packageName: String, label: String) {
        if (packageName == context.packageName) return
        prefs(context).edit()
            .putString(KEY_TARGET_BROWSER_PKG, packageName)
            .putString(KEY_TARGET_BROWSER_NAME, label)
            .apply()
    }

    fun getSavedTargetBrowser(context: Context): BrowserInfo? {
        val p = prefs(context)
        val pkg = p.getString(KEY_TARGET_BROWSER_PKG, null) ?: return null
        if (pkg == context.packageName) return null
        val name = p.getString(KEY_TARGET_BROWSER_NAME, null) ?: pkg
        return BrowserInfo(pkg, name)
    }

    fun hasPromptedOnce(context: Context): Boolean =
        prefs(context).getBoolean(KEY_PROMPTED_ONCE, false)

    fun markPromptedOnce(context: Context) {
        prefs(context).edit().putBoolean(KEY_PROMPTED_ONCE, true).apply()
    }

    fun recordLinkCheck(context: Context, blockedOrSuspicious: Boolean) {
        val p = prefs(context)
        val checked = p.getInt(KEY_STATS_CHECKED, 0) + 1
        val blocked = p.getInt(KEY_STATS_BLOCKED, 0) + if (blockedOrSuspicious) 1 else 0
        p.edit()
            .putInt(KEY_STATS_CHECKED, checked)
            .putInt(KEY_STATS_BLOCKED, blocked)
            .apply()
    }

    fun getStats(context: Context): Pair<Int, Int> {
        val p = prefs(context)
        return Pair(p.getInt(KEY_STATS_CHECKED, 0), p.getInt(KEY_STATS_BLOCKED, 0))
    }

    fun markDeclined(context: Context) {
        prefs(context).edit()
            .putBoolean(KEY_USER_DECLINED, true)
            .putLong(KEY_DECLINED_TS, System.currentTimeMillis())
            .apply()
    }

    fun hasDeclinedRecently(context: Context, cooldownMs: Long): Boolean {
        val p = prefs(context)
        if (!p.getBoolean(KEY_USER_DECLINED, false)) return false
        val ts = p.getLong(KEY_DECLINED_TS, 0L)
        return System.currentTimeMillis() - ts < cooldownMs
    }

    fun clearDeclined(context: Context) {
        prefs(context).edit()
            .putBoolean(KEY_USER_DECLINED, false)
            .putLong(KEY_DECLINED_TS, 0L)
            .apply()
    }

    fun markRepromptShown(context: Context) {
        prefs(context).edit()
            .putLong(KEY_LAST_REPROMPT_TS, System.currentTimeMillis())
            .apply()
    }

    fun shouldShowRepromptDialog(context: Context, minIntervalMs: Long = 6L * 60 * 60 * 1000): Boolean {
        val p = prefs(context)
        val last = p.getLong(KEY_LAST_REPROMPT_TS, 0L)
        return System.currentTimeMillis() - last >= minIntervalMs
    }

    /**
     * Lista todos os navegadores reais instalados no dispositivo, excluindo o próprio SecureLink.
     */
    fun getInstalledBrowsers(context: Context): List<BrowserInfo> {
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        val resolveList = queryAllActivities(pm, intent)

        return resolveList
            .mapNotNull { info ->
                val pkg = info.activityInfo?.packageName ?: return@mapNotNull null
                if (pkg == context.packageName || pkg == "android" || isResolverPackage(pkg)) {
                    return@mapNotNull null
                }
                val label = info.loadLabel(pm)?.toString()?.trim().orEmpty().ifEmpty { pkg }
                BrowserInfo(pkg, label)
            }
            .distinctBy { it.packageName }
            .sortedWith(compareBy(
                { pkg ->
                    val idx = PREFERRED_BROWSER_PACKAGES.indexOf(pkg.packageName)
                    if (idx == -1) Int.MAX_VALUE else idx
                },
                { it.label.lowercase() }
            ))
    }

    /**
     * Abre a URL diretamente no navegador salvo pelo usuário (nunca no próprio SecureLink).
     */
    fun openInTargetBrowser(context: Context, rawUrl: String): Boolean {
        val normalizedUrl = normalizeUrl(rawUrl)
        val uri = Uri.parse(normalizedUrl)
        val installed = getInstalledBrowsers(context)

        // Garante que temos um navegador de destino válido e diferente do SecureLink
        val saved = getSavedTargetBrowser(context)
        val targetPkg = when {
            saved != null && installed.any { it.packageName == saved.packageName } -> saved.packageName
            saved != null && isPackageInstalled(context.packageManager, saved.packageName) -> saved.packageName
            else -> pickPreferredBrowser(installed)?.packageName
        }

        if (targetPkg != null && targetPkg != context.packageName) {
            try {
                val intent = Intent(Intent.ACTION_VIEW, uri).apply {
                    setPackage(targetPkg)
                    addCategory(Intent.CATEGORY_BROWSABLE)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(intent)
                Log.d(TAG, "URL aberta em $targetPkg: $normalizedUrl")
                return true
            } catch (e: Exception) {
                Log.w(TAG, "Falha ao abrir em $targetPkg: ${e.message}")
            }
        }

        // Fallback: tenta qualquer outro navegador instalado
        for (browser in installed) {
            if (browser.packageName == targetPkg || browser.packageName == context.packageName) continue
            try {
                val intent = Intent(Intent.ACTION_VIEW, uri).apply {
                    setPackage(browser.packageName)
                    addCategory(Intent.CATEGORY_BROWSABLE)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(intent)
                Log.d(TAG, "URL aberta via fallback em ${browser.packageName}: $normalizedUrl")
                return true
            } catch (_: Exception) {
            }
        }

        Log.e(TAG, "Nenhum navegador externo encontrado para abrir $normalizedUrl")
        return false
    }

    fun normalizeUrl(url: String): String {
        val trimmed = url.trim()
        return if (trimmed.startsWith("http://", ignoreCase = true) ||
            trimmed.startsWith("https://", ignoreCase = true)
        ) {
            trimmed
        } else {
            "https://$trimmed"
        }
    }

    private fun pickPreferredBrowser(installed: List<BrowserInfo>): BrowserInfo? {
        for (preferredPkg in PREFERRED_BROWSER_PACKAGES) {
            val found = installed.firstOrNull { it.packageName == preferredPkg }
            if (found != null) return found
        }
        return installed.firstOrNull()
    }

    private fun isResolverPackage(pkg: String): Boolean {
        val lower = pkg.lowercase()
        return lower == "android" ||
            lower.contains("resolver") ||
            lower.contains("intentresolver") ||
            lower == "com.huawei.android.internal.app" ||
            lower == "com.miui.securitycenter"
    }

    private fun isPackageInstalled(pm: PackageManager, packageName: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun resolveDefaultActivity(pm: PackageManager, intent: Intent): ResolveInfo? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
        }
    }

    private fun queryAllActivities(pm: PackageManager, intent: Intent): List<ResolveInfo> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_ALL.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        }
    }
}
