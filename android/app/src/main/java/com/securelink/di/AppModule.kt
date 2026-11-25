package com.securelink.di

import android.content.Context
import androidx.datastore.preferences.preferencesDataStore
import androidx.datastore.rxjava3.RxDataStore
import com.securelink.data.preferences.PreferencesRepository
import com.securelink.data.repository.BlocklistRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun providePreferencesDataStore(@dagger.hilt.android.qualifiers.ApplicationContext context: Context) =
        RxDataStore(context, "securelink_prefs")

    @Provides
    @Singleton
    fun provideBlocklistDataStore(@dagger.hilt.android.qualifiers.ApplicationContext context: Context) =
        RxDataStore(context, "securelink_blocklist")

    @Provides
    @Singleton
    fun providePreferencesRepository(
        @dagger.hilt.android.qualifiers.ApplicationContext context: Context
    ) = PreferencesRepository(context)

    @Provides
    @Singleton
    fun provideBlocklistRepository(
        @dagger.hilt.android.qualifiers.ApplicationContext context: Context
    ) = BlocklistRepository(context)
}