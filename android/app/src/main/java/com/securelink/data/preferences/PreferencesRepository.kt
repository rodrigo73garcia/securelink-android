package com.securelink.data.preferences

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.datastore.rxjava3.RxDataStore
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import io.reactivex.rxjava3.core.Flowable
import io.reactivex.rxjava3.core.Single
import java.lang.reflect.Type
import java.util.concurrent.ConcurrentHashMap

/**
 * Repositório de preferências usando DataStore (assíncrono, transacional)
 */
class PreferencesRepository @Inject constructor(
    private val context: Context
) {

    private val dataStore = RxDataStore(context, "securelink_prefs")
    
    // Keys
    private val KEY_BRANDS = stringPreferencesKey("brands_json")
    private val KEY_TYPO_THRESHOLD = intPreferencesKey("typo_threshold")
    private val KEY_MIN_DOMAIN_AGE = intPreferencesKey("min_domain_age_days")
    private val KEY_CRITICAL_DOMAIN_AGE = intPreferencesKey("critical_domain_age_days")
    private val KEY_SUSPICIOUS_TLDS = stringPreferencesKey("suspicious_tlds_json")
    private val KEY_PHISHING_KEYWORDS = stringPreferencesKey("phishing_keywords_json")
    private val KEY_RDAP_ENABLED = booleanPreferencesKey("rdap_enabled")
    private val KEY_UNSHORTEN_ENABLED = booleanPreferencesKey("unshorten_enabled")
    private val KEY_RDAP_TIMEOUT = longPreferencesKey("rdap_timeout_ms")
    private val KEY_UNSHORTEN_TIMEOUT = longPreferencesKey("unshorten_timeout_ms")
    private val KEY_VIRUSTOTAL_API_KEY = stringPreferencesKey("virustotal_api_key")
    private val KEY_AUTO_SCAN = booleanPreferencesKey("auto_scan_enabled")
    private val KEY_BLOCKLIST_VERSION = intPreferencesKey("blocklist_version")
    private val KEY_LAST_BLOCKLIST_UPDATE = longPreferencesKey("last_blocklist_update_ms")
    private val KEY_FIRST_RUN = booleanPreferencesKey("first_run")

    private val gson = Gson()
    private val typeBrands = object : TypeToken<List<BrandConfig>>() {}.type
    private val typeStringList = object : TypeToken<List<String>>() {}.type

    // Cache em memória para leituras rápidas
    private val cache = ConcurrentHashMap<String, Any>()

    suspend fun initializeDefaults() {
        val prefs = dataStore.data.firstOrNull()
            ?: return
        
        if (prefs[KEY_FIRST_RUN] != true) {
            // Primeira execução - carrega defaults do assets
            loadDefaultsFromAssets()
            dataStore.edit { it[KEY_FIRST_RUN] = true }
        }
    }

    private suspend fun loadDefaultsFromAssets() {
        try {
            val brandsJson = context.assets.open("brands/br.json").bufferedReader().readText()
            val tldsJson = context.assets.open("config/suspicious_tlds.json").bufferedReader().readText()
            val keywordsJson = context.assets.open("config/phishing_keywords.json").bufferedReader().readText()
            
            dataStore.edit {
                it[KEY_BRANDS] = brandsJson
                it[KEY_SUSPICIOUS_TLDS] = tldsJson
                it[KEY_PHISHING_KEYWORDS] = keywordsJson
                it[KEY_TYPO_THRESHOLD] = 2
                it[KEY_MIN_DOMAIN_AGE] = 30
                it[KEY_CRITICAL_DOMAIN_AGE] = 7
                it[KEY_RDAP_ENABLED] = true
                it[KEY_UNSHORTEN_ENABLED] = true
                it[KEY_RDAP_TIMEOUT] = 5000L
                it[KEY_UNSHORTEN_TIMEOUT] = 10000L
                it[KEY_AUTO_SCAN] = true
                it[KEY_BLOCKLIST_VERSION] = 0
                it[KEY_LAST_BLOCKLIST_UPDATE] = 0L
            }
        } catch (e: Exception) {
            // Fallback para defaults hardcoded
            setDefaults()
        }
    }

    private suspend fun setDefaults() {
        dataStore.edit {
            it[KEY_TYPO_THRESHOLD] = 2
            it[KEY_MIN_DOMAIN_AGE] = 30
            it[KEY_CRITICAL_DOMAIN_AGE] = 7
            it[KEY_RDAP_ENABLED] = true
            it[KEY_UNSHORTEN_ENABLED] = true
            it[KEY_RDAP_TIMEOUT] = 5000L
            it[KEY_UNSHORTEN_TIMEOUT] = 10000L
            it[KEY_AUTO_SCAN] = true
            it[KEY_BLOCKLIST_VERSION] = 0
            it[KEY_LAST_BLOCKLIST_UPDATE] = 0L
        }
    }

    // --- Getters (com cache) ---

    fun getBrands(): List<BrandConfig> = cache.getOrPut("brands") {
        dataStore.data.map { prefs ->
            val json = prefs[KEY_BRANDS] ?: "[]"
            gson.fromJson(json, typeBrands)
        }.first()
    } as List<BrandConfig>

    fun getTypoThreshold(): Int = cache.getOrPut("typo_threshold") {
        dataStore.data.map { it[KEY_TYPO_THRESHOLD] ?: 2 }.first()
    } as Int

    fun getMinDomainAgeDays(): Int = cache.getOrPut("min_domain_age") {
        dataStore.data.map { it[KEY_MIN_DOMAIN_AGE] ?: 30 }.first()
    } as Int

    fun getCriticalDomainAgeDays(): Int = cache.getOrPut("critical_domain_age") {
        dataStore.data.map { it[KEY_CRITICAL_DOMAIN_AGE] ?: 7 }.first()
    } as Int

    fun getSuspiciousTlds(): List<String> = cache.getOrPut("suspicious_tlds") {
        dataStore.data.map { prefs ->
            val json = prefs[KEY_SUSPICIOUS_TLDS] ?: "[]"
            gson.fromJson(json, typeStringList)
        }.first()
    } as List<String>

    fun getPhishingKeywords(): List<String> = cache.getOrPut("phishing_keywords") {
        dataStore.data.map { prefs ->
            val json = prefs[KEY_PHISHING_KEYWORDS] ?: "[]"
            gson.fromJson(json, typeStringList)
        }.first()
    } as List<String>

    fun isRdapEnabled(): Boolean = cache.getOrPut("rdap_enabled") {
        dataStore.data.map { it[KEY_RDAP_ENABLED] ?: true }.first()
    } as Boolean

    fun isUnshortenEnabled(): Boolean = cache.getOrPut("unshorten_enabled") {
        dataStore.data.map { it[KEY_UNSHORTEN_ENABLED] ?: true }.first()
    } as Boolean

    fun getRdapTimeoutMs(): Long = cache.getOrPut("rdap_timeout") {
        dataStore.data.map { it[KEY_RDAP_TIMEOUT] ?: 5000L }.first()
    } as Long

    fun getUnshortenTimeoutMs(): Long = cache.getOrPut("unshorten_timeout") {
        dataStore.data.map { it[KEY_UNSHORTEN_TIMEOUT] ?: 10000L }.first()
    } as Long

    fun getVirustotalApiKey(): String? = cache.getOrPut("virustotal_key") {
        dataStore.data.map { it[KEY_VIRUSTOTAL_API_KEY] }.first()
    } as String?

    fun isAutoScanEnabled(): Boolean = cache.getOrPut("auto_scan") {
        dataStore.data.map { it[KEY_AUTO_SCAN] ?: true }.first()
    } as Boolean

    fun getBlocklistVersion(): Int = cache.getOrPut("blocklist_version") {
        dataStore.data.map { it[KEY_BLOCKLIST_VERSION] ?: 0 }.first()
    } as Int

    fun getLastBlocklistUpdateMs(): Long = cache.getOrPut("last_blocklist_update") {
        dataStore.data.map { it[KEY_LAST_BLOCKLIST_UPDATE] ?: 0L }.first()
    } as Long

    // --- Setters ---

    suspend fun setTypoThreshold(value: Int) {
        cache["typo_threshold"] = value
        dataStore.edit { it[KEY_TYPO_THRESHOLD] = value }
    }

    suspend fun setMinDomainAgeDays(value: Int) {
        cache["min_domain_age"] = value
        dataStore.edit { it[KEY_MIN_DOMAIN_AGE] = value }
    }

    suspend fun setCriticalDomainAgeDays(value: Int) {
        cache["critical_domain_age"] = value
        dataStore.edit { it[KEY_CRITICAL_DOMAIN_AGE] = value }
    }

    suspend fun setRdapEnabled(value: Boolean) {
        cache["rdap_enabled"] = value
        dataStore.edit { it[KEY_RDAP_ENABLED] = value }
    }

    suspend fun setUnshortenEnabled(value: Boolean) {
        cache["unshorten_enabled"] = value
        dataStore.edit { it[KEY_UNSHORTEN_ENABLED] = value }
    }

    suspend fun setAutoScanEnabled(value: Boolean) {
        cache["auto_scan"] = value
        dataStore.edit { it[KEY_AUTO_SCAN] = value }
    }

    suspend fun setVirustotalApiKey(value: String?) {
        cache["virustotal_key"] = value
        dataStore.edit { it[KEY_VIRUSTOTAL_API_KEY] = value ?: "" }
    }

    suspend fun setBlocklistVersion(version: Int) {
        cache["blocklist_version"] = version
        dataStore.edit { it[KEY_BLOCKLIST_VERSION] = version }
    }

    suspend fun setLastUpdateTime(timeMs: Long) {
        cache["last_blocklist_update"] = timeMs
        dataStore.edit { it[KEY_LAST_BLOCKLIST_UPDATE] = timeMs }
    }

    fun invalidateCache() {
        cache.clear()
    }

    // Flows reativos para UI
    val brandsFlow: Flowable<List<BrandConfig>> = dataStore.data.map { prefs ->
        val json = prefs[KEY_BRANDS] ?: "[]"
        gson.fromJson(json, typeBrands)
    }

    val autoScanFlow: Flowable<Boolean> = dataStore.data.map { it[KEY_AUTO_SCAN] ?: true }
}