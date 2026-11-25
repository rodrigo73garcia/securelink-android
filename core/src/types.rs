//! Tipos de dados principais compartilhados entre Rust e Kotlin/Swift via FFI

use serde::{Deserialize, Serialize};
use std::fmt;

/// Resultado completo da análise de um link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// URL original recebida
    pub original_url: String,
    /// URL final após descurtar e seguir redirecionamentos
    pub final_url: String,
    /// Domínio extraído (ex.: "cacaushowbr.com")
    pub domain: String,
    /// Domínio em Punycode se for IDN (ex.: "xn--pple-43d.com")
    pub punycode_domain: Option<String>,
    /// Pontuação de risco 0-100 (0 = seguro, 100 = golpista confirmado)
    pub risk_score: u8,
    /// Classificação textual
    pub verdict: Verdict,
    /// Motivos detalhados em português para exibição ao usuário
    pub reasons: Vec<Reason>,
    /// Marca imitada se detectado typosquatting
    pub impersonated_brand: Option<String>,
    /// Idade do domínio em dias (None se falhou RDAP)
    pub domain_age_days: Option<u32>,
    /// Se o domínio usa caracteres homógrafos (cirílico, grego, etc.)
    pub has_homograph: bool,
    /// Se o domínio está em lista de bloqueio offline
    pub in_blocklist: bool,
    /// Timestamp da análise (UNIX epoch ms)
    pub analyzed_at_ms: i64,
}

/// Classificação de risco para UI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Verde - seguro para abrir
    Safe,
    /// Amarelo - suspeito, usuário decide
    Suspicious,
    /// Vermelho - bloquear e alertar
    Blocked,
}

impl Verdict {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=29 => Verdict::Safe,
            30..=69 => Verdict::Suspicious,
            _ => Verdict::Blocked,
        }
    }

    pub fn color_hex(&self) -> &'static str {
        match self {
            Verdict::Safe => "#2E7D32",      // Verde escuro
            Verdict::Suspicious => "#F9A825", // Amarelo/laranja
            Verdict::Blocked => "#C62828",    // Vermelho escuro
        }
    }

    pub fn label_pt(&self) -> &'static str {
        match self {
            Verdict::Safe => "Seguro",
            Verdict::Suspicious => "Suspeito",
            Verdict::Blocked => "PERIGO",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Motivo individual de detecção (explicável para o usuário)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reason {
    /// Código interno (para logs/telemetria anônima)
    pub code: ReasonCode,
    /// Texto em português para exibição ao usuário leigo
    pub message_pt: String,
    /// Severidade do motivo
    pub severity: Severity,
}

/// Códigos de motivo padronizados
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    // Homógrafos/IDN
    HomographCyrillic,
    HomographGreek,
    HomographMixedScripts,
    PunnycodeDetected,
    // Typosquatting
    TyposquattingBrand,
    CombosquattingBrand,
    LeetSpeakSubstitution,
    SubdomainTrick,
    // Idade/Infraestrutura
    DomainTooNew,
    DomainVeryNew,
    SuspiciousTld,
    IpAsHostname,
    // Listas de bloqueio
    InPhishingBlocklist,
    InMalwareBlocklist,
    // Conteúdo/Comportamento
    UrlShortener,
    ExcessiveSubdomains,
    ExcessivePathDepth,
    PhishingKeywordsInUrl,
    // Heurísticas gerais
    LowDomainRank,
    NoTls,
    RedirectChain,
    CrossDomainRedirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Configuração do motor (carregada do assets/config.json no Android)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Lista de marcas para typosquatting (carregada de brands/*.yaml)
    pub brands: Vec<BrandEntry>,
    /// Threshold de distância de edição para typosquatting (padrão: 2)
    pub typo_threshold: usize,
    /// Idade mínima em dias para considerar domínio "estabelecido" (padrão: 30)
    pub min_domain_age_days: u32,
    /// Idade crítica em dias (padrão: 7)
    pub critical_domain_age_days: u32,
    /// TLDs suspeitos
    pub suspicious_tlds: Vec<String>,
    /// Palavras-chave de phishing em URLs
    pub phishing_keywords: Vec<String>,
    /// Habilitar verificação RDAP online (padrão: true)
    pub enable_rdap: bool,
    /// Habilitar descurtador de URLs (padrão: true)
    pub enable_unshorten: bool,
    /// Timeout RDAP em ms (padrão: 5000)
    pub rdap_timeout_ms: u64,
    /// Timeout descurtador em ms (padrão: 10000)
    pub unshorten_timeout_ms: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            brands: Vec::new(),
            typo_threshold: 2,
            min_domain_age_days: 30,
            critical_domain_age_days: 7,
            suspicious_tlds: vec![
                "top".into(), "xyz".into(), "click".into(), "loan".into(),
                "work".into(), "party".into(), "gdn".into(), "bid".into(),
                "racing".into(), "online".into(), "site".into(), "website".into(),
                "space".into(), "tech".into(), "store".into(), "shop".into(),
                "club".into(), "fun".into(), "live".into(), "link".into(),
            ],
            phishing_keywords: vec![
                "login".into(), "verify".into(), "secure".into(), "update".into(),
                "confirm".into(), "validate".into(), "authenticate".into(),
                "account".into(), "password".into(), "credential".into(),
                "bank".into(), "paypal".into(), "apple".into(), "microsoft".into(),
                "google".into(), "amazon".into(), "netflix".into(),
                "promocao".into(), "promoção".into(), "oferta".into(), "desconto".into(),
                "gratis".into(), "grátis".into(), "premio".into(), "prêmio".into(),
                "resgate".into(), "sorteio".into(), "urgente".into(),
                "pendente".into(), "taxa".into(), "alfandega".into(),
            ],
            enable_rdap: true,
            enable_unshorten: true,
            rdap_timeout_ms: 5000,
            unshorten_timeout_ms: 10000,
        }
    }
}

/// Entrada de marca monitorada
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandEntry {
    /// Nome da marca (ex.: "Cacau Show")
    pub name: String,
    /// Domínio oficial (ex.: "cacaushow.com.br")
    pub official_domain: String,
    /// Domínios oficiais adicionais (ex.: ["cacaushow.com", "cacaushowbrasil.com.br"])
    #[serde(default)]
    pub alt_domains: Vec<String>,
    /// Palavras-chave da marca para detectar no caminho da URL
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Prioridade (maior = mais importante, padrão: 100)
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_priority() -> u32 { 100 }

/// Resposta simplificada para FFI (JNI/Swift)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiAnalysisResult {
    pub final_url: String,
    pub risk_score: u8,
    pub verdict: Verdict,
    pub reasons: Vec<FfiReason>,
    pub impersonated_brand: Option<String>,
    pub domain_age_days: Option<u32>,
    pub has_homograph: bool,
    pub in_blocklist: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiReason {
    pub code: String,
    pub message_pt: String,
    pub severity: String,
}

impl From<AnalysisResult> for FfiAnalysisResult {
    fn from(r: AnalysisResult) -> Self {
        Self {
            final_url: r.final_url,
            risk_score: r.risk_score,
            verdict: r.verdict,
            reasons: r.reasons.into_iter().map(|x| FfiReason {
                code: format!("{:?}", x.code),
                message_pt: x.message_pt,
                severity: format!("{:?}", x.severity),
            }).collect(),
            impersonated_brand: r.impersonated_brand,
            domain_age_days: r.domain_age_days,
            has_homograph: r.has_homograph,
            in_blocklist: r.in_blocklist,
        }
    }
}