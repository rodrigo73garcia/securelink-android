# ProGuard rules for SecureLink

# Keep JNI native methods
-keep class com.securelink.core.SecureLinkEngine {
    native <methods>;
    public static *;
}

# Keep data classes for serialization
-keep class com.securelink.core.** { *; }
-keep class com.securelink.data.** { *; }
-keep class com.securelink.ui.** { *; }

# Keep Room entities and DAOs
-keep class com.securelink.data.db.** { *; }

# Keep Hilt generated classes
-keep class dagger.hilt.** { *; }
-keep class * extends dagger.hilt.android.HiltAndroidApp
-keep class * extends dagger.hilt.android.EntryPoint
-keep class * extends dagger.hilt.ActivityRetainedComponent

# Keep Kotlin coroutines
-keep class kotlinx.coroutines.** { *; }

# Keep Kotlinx serialization
-keep class kotlinx.serialization.** { *; }
-keep @kotlinx.serialization.Serializable class *

# Keep Gson
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapter
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# Keep DataStore
-keep class androidx.datastore.** { *; }

# Keep WorkManager
-keep class androidx.work.** { *; }

# Keep Material Components
-keep class com.google.android.material.** { *; }

# Keep Coil
-keep class coil.** { *; }

# Keep Timber
-keep class timber.log.** { *; }

# Don't warn about missing native libraries during build
-dontwarn com.securelink.core.SecureLinkEngine

# Keep native library loading
-keep class java.lang.System { 
    public static void loadLibrary(java.lang.String); 
}