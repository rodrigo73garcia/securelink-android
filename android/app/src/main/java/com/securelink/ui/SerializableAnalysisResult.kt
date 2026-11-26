package com.securelink.ui

import java.io.Serializable

data class SerializableAnalysisResult(
    val originalUrl: String,
    val finalUrl: String,
    val riskScore: Int,
    val verdict: String,
    val reasons: List<String>,
    val impersonatedBrand: String?,
    val officialDomain: String?,
    val hasHomograph: Boolean
) : Serializable
