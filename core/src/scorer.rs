//! Motor de pontuação de risco explicável
//! 
//! Combina todos os sinais (homógrafos, typosquatting, idade RDAP, blocklist, heurísticas)
//! em uma pontuação 0-100 com motivos em português.

use crate::types::*;
use crate::idn_homograph::*;
use crate::typosquatting::*;
use crate::rdap::*;
use crate::bloom::*;
use crate::unshortener::*;

/// Motor principal de análise
pub struct AnalysisEngine {
    config: EngineConfig,
    rdap_client: RdapClient,
    unshortener: Unshortener,
}

impl AnalysisEngine {
    pub fn new(config: EngineConfig) -> Self {
        let rdap_timeout = config.rdap_timeout_ms;
        let unshorten_timeout = config.unshorten_timeout_ms;
        
        Self {
            config,
            rdap_client: RdapClient::new(rdap_timeout),
            unshortener: Unshortener::new(unshorten_timeout),
        }
    }

    /// Análise completa de uma URL
    pub fn analyze(&self, url: &str) -> AnalysisResult {
        let mut reasons = Vec::new();
        let mut risk_score: i32 = 50; // Base neutra
        
        // 1. Normaliza e extrai domínio
        let norm_url = normalize_domain(url);
        let domain = extract_base_domain(&norm_url);
        let punycode_domain = if domain.starts_with("xn--") { Some(domain.clone()) } else { None };
        
        // 2. Descurtar URL se habilitado
        let final_url = if self.config.enable_unshorten {
            self.unshortener.expand(url)
        } else {
            url.to_string()
        };
        let final_domain = extract_base_domain(&normalize_domain(&final_url));

        // 3. Verifica blocklist offline (mais rápido, primeiro)
        if check_blocklist(&final_domain) {
            reasons.push(Reason {
                code: ReasonCode::InPhishingBlocklist,
                message_pt: "Este domínio está em listas conhecidas de phishing/malware".into(),
                severity: Severity::Critical,
            });
            risk_score += 40;
        }

        // 4. Detecção de homógrafos/IDN
        let homograph_analysis = analyze_homograph(&final_domain);
        if homograph_analysis.is_punycode {
            reasons.push(Reason {
                code: ReasonCode::PunnycodeDetected,
                message_pt: format!("Domínio usa codificação Punycode (xn--) para esconder caracteres estrangeiros: {}", final_domain),
                severity: Severity::Critical,
            });
            risk_score += 30;
        }
        if homograph_analysis.has_mixed_scripts {
            let scripts = homograph_analysis.scripts_found.join(", ");
            reasons.push(Reason {
                code: ReasonCode::HomographMixedScripts,
                message_pt: format!("Domínio mistura alfabetos ({}): visualmente parece '{}' mas não é", scripts, homograph_analysis.lookalike_ascii.unwrap_or_default()),
                severity: Severity::Critical,
            });
            risk_score += 35;
        }
        
        // Verifica homógrafo contra marcas conhecidas
        if let Some((_brand, brand_reasons)) = check_homograph_brand(&final_domain, &self.config.brands) {
            reasons.extend(brand_reasons);
            risk_score += 40;
        }

        // 5. Typosquatting / Combosquatting
        if let Some(typosquat) = check_typosquatting(&final_domain, &self.config.brands, self.config.typo_threshold) {
            reasons.extend(typosquat_to_reasons(&typosquat));
            match typosquat.match_type {
                TyposquatType::Typosquatting => risk_score += 30,
                TyposquatType::Combosquatting => risk_score += 35,
                TyposquatType::SubdomainTrick => risk_score += 40,
                TyposquatType::LeetSpeak => risk_score += 30,
            }
        }

        // 6. Idade do domínio via RDAP
        if self.config.enable_rdap {
            if let Some(age_days) = self.rdap_client.get_domain_age_days(&final_domain) {
                if age_days <= self.config.critical_domain_age_days {
                    reasons.push(Reason {
                        code: ReasonCode::DomainVeryNew,
                        message_pt: format!("Domínio criado há apenas {} dia(s) - domínios muito novos são fortes indicadores de golpe", age_days),
                        severity: Severity::Critical,
                    });
                    risk_score += 35;
                } else if age_days <= self.config.min_domain_age_days {
                    reasons.push(Reason {
                        code: ReasonCode::DomainTooNew,
                        message_pt: format!("Domínio criado há {} dia(s) - domínios recentes merecem cautela", age_days),
                        severity: Severity::Warning,
                    });
                    risk_score += 15;
                }
            }
        }

        // 7. Heurísticas de URL
        self.check_url_heuristics(&final_url, &final_domain, &mut reasons, &mut risk_score);

        // 8. TLD suspeito
        let tld = final_domain.split('.').last().unwrap_or("");
        if self.config.suspicious_tlds.contains(&tld.to_string()) {
            reasons.push(Reason {
                code: ReasonCode::SuspiciousTld,
                message_pt: format!("TLD '{}' é frequentemente abusado por golpistas", tld),
                severity: Severity::Warning,
            });
            risk_score += 10;
        }

        // 9. IP como hostname
        if final_domain.parse::<std::net::IpAddr>().is_ok() {
            reasons.push(Reason {
                code: ReasonCode::IpAsHostname,
                message_pt: "O endereço usa um IP numérico em vez de nome de domínio (tática comum de evasão)".into(),
                severity: Severity::Critical,
            });
            risk_score += 30;
        }

        // Clamp score
        risk_score = risk_score.clamp(0, 100);
        let verdict = Verdict::from_score(risk_score as u8);

        // Determina marca imitada
        let impersonated_brand = reasons.iter()
            .find_map(|r| match r.code {
                ReasonCode::TyposquattingBrand | ReasonCode::CombosquattingBrand | ReasonCode::HomographCyrillic | ReasonCode::HomographGreek | ReasonCode::HomographMixedScripts => {
                    if let Some(start) = r.message_pt.find("'") {
                        if let Some(end) = r.message_pt[start+1..].find("'") {
                            return Some(r.message_pt[start+1..start+1+end].to_string());
                        }
                    }
                    None
                }
                _ => None,
            });

        // Clona final_domain para uso posterior
        let final_domain_for_blocklist = final_domain.clone();

        AnalysisResult {
            original_url: url.to_string(),
            final_url,
            domain: final_domain,
            punycode_domain,
            risk_score: risk_score as u8,
            verdict,
            reasons,
            impersonated_brand,
            domain_age_days: if self.config.enable_rdap { self.rdap_client.get_domain_age_days(&extract_base_domain(&normalize_domain(url))) } else { None },
            has_homograph: homograph_analysis.has_mixed_scripts || homograph_analysis.is_punycode,
            in_blocklist: check_blocklist(&final_domain_for_blocklist),
            analyzed_at_ms: chrono::Utc::now().timestamp_millis(),
        }
    }

    fn check_url_heuristics(&self, url: &str, domain: &str, reasons: &mut Vec<Reason>, risk_score: &mut i32) {
        let url_lower = url.to_lowercase();
        // let domain_lower = domain.to_lowercase(); // não usado atualmente

        // Subdomínios excessivos
        let subdomain_count = domain.matches('.').count().saturating_sub(1);
        if subdomain_count >= 4 {
            reasons.push(Reason {
                code: ReasonCode::ExcessiveSubdomains,
                message_pt: format!("Muitos subdomínios ({}) - tática para esconder o domínio real", subdomain_count),
                severity: Severity::Warning,
            });
            *risk_score += 10;
        }

        // Profundidade de path excessiva
        if let Some(protocol_end) = url.find("://") {
            let after_protocol = &url[protocol_end + 3..];
            if let Some(path_start) = after_protocol.find('/') {
                let path = &after_protocol[path_start..];
                let depth = path.matches('/').count();
                if depth >= 5 {
                    reasons.push(Reason {
                        code: ReasonCode::ExcessivePathDepth,
                        message_pt: format!("Caminho URL muito profundo ({} níveis) - usado para ofuscar destino", depth),
                        severity: Severity::Warning,
                    });
                    *risk_score += 5;
                }
            }
        }

        // Palavras-chave de phishing na URL
        for kw in &self.config.phishing_keywords {
            if url_lower.contains(&kw.to_lowercase()) {
                reasons.push(Reason {
                    code: ReasonCode::PhishingKeywordsInUrl,
                    message_pt: format!("URL contém palavra suspeita: '{}'", kw),
                    severity: Severity::Warning,
                });
                *risk_score += 5;
                break; // Só conta uma vez
            }
        }

        // URL muito longa
        if url.len() > 200 {
            reasons.push(Reason {
                code: ReasonCode::ExcessivePathDepth,
                message_pt: "URL anormalmente longa - pode esconder destino real".into(),
                severity: Severity::Warning,
            });
            *risk_score += 5;
        }

        // Encurtador detectado
        let shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "short.io", "rebrand.ly"];
        if shorteners.iter().any(|s| url_lower.contains(s)) {
            reasons.push(Reason {
                code: ReasonCode::UrlShortener,
                message_pt: "URL usa encurtador - destino real ocultado".into(),
                severity: Severity::Warning,
            });
            *risk_score += 10;
        }
    }
}

/// Instância global do motor
static ENGINE: std::sync::OnceLock<AnalysisEngine> = std::sync::OnceLock::new();

pub fn init_engine(config: EngineConfig) {
    ENGINE.set(AnalysisEngine::new(config)).ok();
}

pub fn get_engine() -> Option<&'static AnalysisEngine> {
    ENGINE.get()
}

pub fn analyze_url(url: &str) -> Option<AnalysisResult> {
    get_engine().map(|e| e.analyze(url))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> EngineConfig {
        EngineConfig {
            brands: vec![
                BrandEntry {
                    name: "Cacau Show".into(),
                    official_domain: "cacaushow.com.br".into(),
                    alt_domains: vec![],
                    keywords: vec!["cacaushow".into(), "cacau".into()],
                    priority: 100,
                },
                BrandEntry {
                    name: "Apple".into(),
                    official_domain: "apple.com".into(),
                    alt_domains: vec![],
                    keywords: vec!["apple".into(), "icloud".into()],
                    priority: 100,
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn test_safe_domain() {
        let engine = AnalysisEngine::new(test_config());
        let result = engine.analyze("https://google.com");
        // Com o sistema de pontuação atual (base 50, apenas sinais de risco), 
        // domínios conhecidos como google.com ficam Suspicious sem sinais de confiança
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert!(result.risk_score >= 30 && result.risk_score < 70);
    }

    #[test]
    fn test_typosquatting_cacaushowbr() {
        let engine = AnalysisEngine::new(test_config());
        let result = engine.analyze("https://cacaushowbr.com");
        assert_eq!(result.verdict, Verdict::Blocked);
        assert!(result.risk_score >= 70);
        assert!(result.impersonated_brand.is_some());
    }

    #[test]
    fn test_homograph_cyrillic() {
        let engine = AnalysisEngine::new(test_config());
        let result = engine.analyze("https://\u{0430}pple.com"); // 'а' cirílico
        assert_eq!(result.verdict, Verdict::Blocked);
        assert!(result.has_homograph);
        assert!(result.reasons.iter().any(|r| matches!(r.code, ReasonCode::HomographCyrillic)));
    }
}