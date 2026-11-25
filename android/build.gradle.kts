// Top-level build file
plugins {
    id 'com.android.application' version '8.3.0' apply false
    id 'org.jetbrains.kotlin.android' version '1.9.20' apply false
    id 'com.github.ziadk.r8' version '1.0.0' apply false
}

ext {
    kotlin_version = '1.9.20'
    agp_version = '8.3.0'
    compile_sdk = 34
    min_sdk = 24
    target_sdk = 34
    ndk_version = '26.1.10909125'
}

tasks.register("clean", Delete) {
    delete rootProject.buildDir
}