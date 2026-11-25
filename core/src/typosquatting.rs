//! Detecção de typosquatting e combosquatting contra lista de marcas monitoradas
//! 
//! Algoritmos:
//! - Distância de Levenshtein (edição)
//! - Jaro-Winkler (similaridade de prefixo)
//! - Detecção de leet speak (0=o, 1=l, 3=e, 4=a, 5=s, 7=t, 8=b, @=a)
//! - Combosquatting (marca + palavra: cacaushow-promo.com)
//! - Subdomain trick (marca.com.phishersite.com)

use crate::types::*;
use strsim::{levenshtein, jaro_winkler};
use std::collections::HashSet;

/// Normaliza domínio para comparação (remove TLD, www, etc.)
pub fn normalize_domain(domain: &str) -> String {
    let domain = domain.to_lowercase().trim().to_string();
    // Remove protocolo se houver
    let domain = domain.strip_prefix("http://").unwrap_or(&domain);
    let domain = domain.strip_prefix("https://").unwrap_or(domain);
    // Remove www.
    let domain = domain.strip_prefix("www.").unwrap_or(domain);
    // Remove path/query/fragment
    let domain = domain.split('/').next().unwrap_or(domain);
    let domain = domain.split('?').next().unwrap_or(domain);
    let domain = domain.split('#').next().unwrap_or(domain);
    // Remove porta
    let domain = domain.split(':').next().unwrap_or(domain);
    domain.to_string()
}

/// Extrai o domínio base (SLD + TLD) para comparação de marca
/// ex.: "sub.cacaushow.com.br" -> "cacaushow.com.br"
pub fn extract_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        // Para .com.br, .gov.br, etc., pega os últimos 3
        let tld = parts[parts.len() - 1];
        let sld = parts[parts.len() - 2];
        let third = if parts.len() >= 3 {
            parts[parts.len() - 3]
        } else {
            ""
        };
        
        // Lista de TLDs de dois níveis comuns no Brasil
        let two_level_tlds = ["com.br", "gov.br", "edu.br", "org.br", "net.br", "mil.br", "art.br", "blog.br", "wiki.br"];
        let possible_two_level = format!("{}.{}", sld, tld);
        
        if two_level_tlds.contains(&possible_two_level.as_str()) {
            if !third.is_empty() {
                return format!("{}.{}.{}", third, sld, tld);
            }
        }
        format!("{}.{}", sld, tld)
    } else {
        domain.to_string()
    }
}

/// Normalização leet speak para comparação
pub fn normalize_leet(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o', '1' => 'l', '3' => 'e', '4' => 'a',
            '5' => 's', '7' => 't', '8' => 'b', '@' => 'a',
            '$' => 's', '+' => 't', '!' => 'i', '|' => 'l',
            '[' => 'a', ']' => 'a', '{' => 'a', '}' => 'a',
            '(' => 'c', ')' => 'c', '<' => 'c', '>' => 'c',
            '_' => '-', '*' => 'x', '#' => 'h', '&' => 'a',
            c => c,
        })
        .collect()
}

/// Resultado da verificação de typosquatting
#[derive(Debug, Clone)]
pub struct TyposquatMatch {
    pub brand: BrandEntry,
    pub matched_domain: String,       // domínio que bateu (ex.: "cacaushowbr")
    pub official_domain: String,      // domínio oficial (ex.: "cacaushow.com.br")
    pub distance: usize,              // distância de edição
    pub similarity: f64,              // Jaro-Winkler 0.0-1.0
    pub match_type: TyposquatType,
    pub matched_keyword: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TyposquatType {
    /// Troca/adição/remoção de caracteres: cacaushowbr.com
    Typosquatting,
    /// Marca + palavra: cacaushow-promo.com, cacaushowlogin.com
    Combosquatting,
    /// Subdomínio enganoso: cacaushow.com.phisher.com
    SubdomainTrick,
    /// Leet speak: cac4ush0w.com
    LeetSpeak,
}

/// Verifica typosquatting/combosquatting contra lista de marcas
pub fn check_typosquatting(domain: &str, brands: &[BrandEntry], threshold: usize) -> Option<TyposquatMatch> {
    let norm_domain = normalize_domain(domain);
    let base_domain = extract_base_domain(&norm_domain);
    let base_domain_parts: Vec<&str> = base_domain.split('.').collect();
    let sld = base_domain_parts.first().unwrap_or(&"");
    
    // Verifica subdomain trick primeiro (marca.com.evil.com)
    // Usa o domínio normalizado completo para detectar marca nos subdomínios
    let full_domain_parts: Vec<&str> = norm_domain.split('.').collect();
    if full_domain_parts.len() >= 3 {
        // Verifica todos os prefixos possíveis do subdomínio (exceto o domínio base real)
        // O domínio base real são os últimos 2-3 partes
        let base_domain_parts = base_domain_parts.len();
        let subdomain_parts_count = full_domain_parts.len() - base_domain_parts;
        
        if subdomain_parts_count >= 2 {
            // Verifica todos os prefixos do subdomínio com 2+ partes
            for prefix_len in 2..=subdomain_parts_count.min(4) {
                let possible_brand_domain = full_domain_parts[..prefix_len].join(".");
                for brand in brands {
                    let brand_base = extract_base_domain(&brand.official_domain);
                    if possible_brand_domain.eq_ignore_ascii_case(&brand_base) {
                        return Some(TyposquatMatch {
                            brand: brand.clone(),
                            matched_domain: norm_domain.clone(),
                            official_domain: brand.official_domain.clone(),
                            distance: 0,
                            similarity: 1.0,
                            match_type: TyposquatType::SubdomainTrick,
                            matched_keyword: None,
                        });
                    }
                }
            }
        }
    }

    // Verifica cada marca
    let mut best_match: Option<TyposquatMatch> = None;
    let mut best_score = f64::MAX; // menor distância = melhor

    for brand in brands {
        let brand_base = extract_base_domain(&brand.official_domain);
        let brand_sld = brand_base.split('.').next().unwrap_or("");
        let brand_keywords = &brand.keywords;

        // 1. Typosquatting direto no SLD
        let dist = levenshtein(sld, brand_sld);
        let sim = jaro_winkler(sld, brand_sld);
        
        if dist <= threshold && dist > 0 && sim > 0.7 {
            let score = dist as f64 * (1.0 - sim);
            if score < best_score {
                best_score = score;
                best_match = Some(TyposquatMatch {
                    brand: brand.clone(),
                    matched_domain: norm_domain.clone(),
                    official_domain: brand.official_domain.clone(),
                    distance: dist,
                    similarity: sim,
                    match_type: TyposquatType::Typosquatting,
                    matched_keyword: None,
                });
            }
        }

        // 2. Leet speak no SLD
        let leet_sld = normalize_leet(sld);
        let leet_dist = levenshtein(&leet_sld, brand_sld);
        // Permite leet_dist == 0 se a distância original era grande (leet normalization ajudou)
        if leet_dist <= threshold && (leet_dist > 0 || dist > threshold) && leet_dist != dist {
            let leet_sim = jaro_winkler(&leet_sld, brand_sld);
            let score = leet_dist as f64 * (1.0 - leet_sim);
            if score < best_score {
                best_score = score;
                best_match = Some(TyposquatMatch {
                    brand: brand.clone(),
                    matched_domain: norm_domain.clone(),
                    official_domain: brand.official_domain.clone(),
                    distance: leet_dist,
                    similarity: leet_sim,
                    match_type: TyposquatType::LeetSpeak,
                    matched_keyword: None,
                });
            }
        }

        // 3. Combosquatting: marca + palavra no SLD
        // ex.: cacaushowpromo, cacaushow-login, cacaushowbrasil
        for keyword in brand_keywords {
            let combined = format!("{}{}", brand_sld, keyword);
            let combined_hyphen = format!("{}-{}", brand_sld, keyword);
            let combined_hyphen_rev = format!("{}-{}", keyword, brand_sld);
            
            for variant in [&combined, &combined_hyphen, &combined_hyphen_rev] {
                let dist = levenshtein(sld, variant);
                let sim = jaro_winkler(sld, variant);
                if dist <= threshold + 2 && sim > 0.6 { // threshold mais alto para combos
                    let score = dist as f64 * (1.0 - sim);
                    if score < best_score {
                        best_score = score;
                        best_match = Some(TyposquatMatch {
                            brand: brand.clone(),
                            matched_domain: norm_domain.clone(),
                            official_domain: brand.official_domain.clone(),
                            distance: dist,
                            similarity: sim,
                            match_type: TyposquatType::Combosquatting,
                            matched_keyword: Some(keyword.clone()),
                        });
                    }
                }
            }
        }

        // 4. Verifica palavras-chave da marca no caminho completo da URL (path)
        // Útil para detectar: evilsite.com/cacaushow-promo
        let full_path = norm_domain.replace(&base_domain, "");
        for keyword in brand_keywords {
            if full_path.to_lowercase().contains(&keyword.to_lowercase()) {
                // Marca aparece no path mas domínio não é oficial
                let score = 10.0; // score fixo médio
                if score < best_score {
                    best_score = score;
                    best_match = Some(TyposquatMatch {
                        brand: brand.clone(),
                        matched_domain: norm_domain.clone(),
                        official_domain: brand.official_domain.clone(),
                        distance: 0,
                        similarity: 0.8,
                        match_type: TyposquatType::Combosquatting,
                        matched_keyword: Some(keyword.clone()),
                    });
                }
            }
        }
    }

    best_match
}

/// Converte match em Reasons para o resultado final
pub fn typosquat_to_reasons(m: &TyposquatMatch) -> Vec<Reason> {
    let mut reasons = Vec::new();

    match m.match_type {
        TyposquatType::Typosquatting => {
            reasons.push(Reason {
                code: ReasonCode::TyposquattingBrand,
                message_pt: format!(
                    "O endereço '{}' imita a marca '{}' ({}) com apenas {} caractere(s) diferente(s)",
                    m.matched_domain, m.brand.name, m.official_domain, m.distance
                ),
                severity: if m.distance == 1 { Severity::Critical } else { Severity::Warning },
            });
        }
        TyposquatType::Combosquatting => {
            let kw = m.matched_keyword.as_deref().unwrap_or("palavra suspeita");
            reasons.push(Reason {
                code: ReasonCode::CombosquattingBrand,
                message_pt: format!(
                    "O endereço '{}' usa o nome '{}' junto com '{}' para parecer oficial, mas o domínio verdadeiro é '{}'",
                    m.matched_domain, m.brand.name, kw, m.official_domain
                ),
                severity: Severity::Critical,
            });
        }
        TyposquatType::SubdomainTrick => {
            reasons.push(Reason {
                code: ReasonCode::SubdomainTrick,
                message_pt: format!(
                    "Golpe de subdomínio: '{}' coloca '{}' no subdomínio, mas o site real é '{}' (o domínio verdadeiro é o final: {})",
                    m.matched_domain, m.brand.name, m.official_domain, 
                    m.matched_domain.split('.').rev().take(2).collect::<Vec<_>>().join(".")
                ),
                severity: Severity::Critical,
            });
        }
        TyposquatType::LeetSpeak => {
            reasons.push(Reason {
                code: ReasonCode::LeetSpeakSubstitution,
                message_pt: format!(
                    "O endereço '{}' substitui letras por números/símbolos (ex.: 4=A, 0=O, 1=I) para imitar '{}'",
                    m.matched_domain, m.official_domain
                ),
                severity: Severity::Critical,
            });
        }
    }

    reasons
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_brands() -> Vec<BrandEntry> {
        vec![
            BrandEntry {
                name: "Cacau Show".into(),
                official_domain: "cacaushow.com.br".into(),
                alt_domains: vec!["cacaushow.com".into()],
                keywords: vec!["cacaushow".into(), "cacau".into(), "show".into(), "promo".into(), "promocao".into()],
                priority: 100,
            },
            BrandEntry {
                name: "Nubank".into(),
                official_domain: "nubank.com.br".into(),
                alt_domains: vec![],
                keywords: vec!["nubank".into(), "nu".into(), "conta".into(), "cartao".into()],
                priority: 100,
            },
            BrandEntry {
                name: "Apple".into(),
                official_domain: "apple.com".into(),
                alt_domains: vec!["icloud.com".into()],
                keywords: vec!["apple".into(), "icloud".into(), "id".into(), "support".into()],
                priority: 100,
            },
        ]
    }

    #[test]
    fn test_typosquatting_cacaushowbr() {
        let brands = test_brands();
        let result = check_typosquatting("cacaushowbr.com", &brands, 2);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.brand.name, "Cacau Show");
        assert_eq!(m.match_type, TyposquatType::Typosquatting);
        assert_eq!(m.distance, 2); // "cacaushowbr" vs "cacaushow" = +br
    }

    #[test]
    fn test_combosquatting_cacaushow_promo() {
        let brands = test_brands();
        let result = check_typosquatting("cacaushowpromo.com", &brands, 3);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.match_type, TyposquatType::Combosquatting);
        assert_eq!(m.matched_keyword, Some("promo".into()));
    }

    #[test]
    fn test_subdomain_trick() {
        let brands = test_brands();
        let result = check_typosquatting("cacaushow.com.br.evil.com", &brands, 2);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.match_type, TyposquatType::SubdomainTrick);
    }

    #[test]
    fn test_leetspeak() {
        let brands = test_brands();
        let result = check_typosquatting("c4c4ush0w.com", &brands, 2);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.match_type, TyposquatType::LeetSpeak);
    }

    #[test]
    fn test_normal_domain_safe() {
        let brands = test_brands();
        let result = check_typosquatting("google.com", &brands, 2);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_base_domain_br() {
        assert_eq!(extract_base_domain("cacaushow.com.br"), "cacaushow.com.br");
        assert_eq!(extract_base_domain("www.cacaushow.com.br"), "cacaushow.com.br");
        assert_eq!(extract_base_domain("shop.cacaushow.com.br"), "cacaushow.com.br");
        assert_eq!(extract_base_domain("apple.com"), "apple.com");
        // .co.uk não está na lista de TLDs brasileiros, então retorna apenas co.uk
        assert_eq!(extract_base_domain("sub.domain.co.uk"), "co.uk");
    }
}