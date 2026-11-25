package com.securelink.data.repository

import android.content.Context
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.datastore.rxjava3.RxDataStore
import io.reactivex.rxjava3.core.Single
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BlocklistRepository @Inject constructor(
    private val context: Context
) {

    private val dataStore = RxDataStore(context, "securelink_blocklist")
    
    private val KEY_VERSION = intPreferencesKey("blocklist_version")
    private val KEY_LAST_UPDATE = longPreferencesKey("last_update_ms")
    private val KEY_SOURCE_HASH = stringPreferencesKey("source_hash")

    suspend fun getBlocklistVersion(): Int {
        return dataStore.data.map { it[KEY_VERSION] ?: 0 }.first()
    }

    suspend fun setBlocklistVersion(version: Int) {
        dataStore.edit { it[KEY_VERSION] = version }
    }

    suspend fun getLastUpdateTimeMs(): Long {
        return dataStore.data.map { it[KEY_LAST_UPDATE] ?: 0L }.first()
    }

    suspend fun setLastUpdateTime(timeMs: Long) {
        dataStore.edit { it[KEY_LAST_UPDATE] = timeMs }
    }

    suspend fun getSourceHash(): String? {
        return dataStore.data.map { it[KEY_SOURCE_HASH] }.first()
    }

    suspend fun setSourceHash(hash: String) {
        dataStore.edit { it[KEY_SOURCE_HASH] = hash }
    }

    suspend fun reset() {
        dataStore.edit {
            it[KEY_VERSION] = 0
            it[KEY_LAST_UPDATE] = 0L
            it[KEY_SOURCE_HASH] = ""
        }
    }
}