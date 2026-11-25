package com.securelink.data.preferences

import com.google.gson.annotations.SerializedName

data class BrandConfig(
    @SerializedName("name") val name: String,
    @SerializedName("official_domain") val officialDomain: String,
    @SerializedName("alt_domains") val altDomains: List<String> = emptyList(),
    @SerializedName("keywords") val keywords: List<String> = emptyList(),
    @SerializedName("priority") val priority: Int = 100
)