//! Consulta RDAP para idade do domínio
//! 
//! RDAP (Registration Data Access Protocol) substituiu WHOIS oficialmente na ICANN (jan/2025).
//! Endpoint público: https://rdap.org/domain/{domain}
//! Retorna JSON estruturado com datas de registro, expiração, registrar, nameservers.

use crate::types::*;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};

/// Cliente RDAP com cache em memória
pub struct RdapClient {
    client: Client,
    cache: std::sync::Mutex<std::collections::HashMap<String, CachedRdap>>,
    timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedRdap {
    data: RdapResponse,
    cached_at: u64, // UNIX epoch ms
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapResponse {
    #[serde(rename = "events")]
    events: Vec<RdapEvent>,
    #[serde(rename = "entities")]
    entities: Option<Vec<RdapEntity>>,
    #[serde(rename = "nameservers")]
    nameservers: Option<Vec<RdapNameserver>>,
    #[serde(rename = "status")]
    status: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    event_action: String,
    #[serde(rename = "eventDate")]
    event_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapEntity {
    #[serde(rename = "roles")]
    roles: Vec<String>,
    #[serde(rename = "vcardArray")]
    vcard_array: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapNameserver {
    #[serde(rename = "ldhName")]
    ldh_name: String,
}

impl RdapClient {
    pub fn new(timeout_ms: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .user_agent("SecureLink/0.1 (+https://github.com/usuario/securelink)")
            .build()
            .expect("Falha ao criar cliente HTTP");

        Self {
            client,
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            timeout_ms,
        }
    }

    /// Consulta idade do domínio em dias (com cache de 30 dias)
    pub fn get_domain_age_days(&self, domain: &str) -> Option<u32> {
        let cache_key = domain.to_lowercase();
        
        // Verifica cache (30 dias = 2_592_000_000 ms)
        if let Ok(cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&cache_key) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis() as u64;
                if now - cached.cached_at < 30 * 24 * 60 * 60 * 1000 {
                    return self.calculate_age_days(&cached.data);
                }
            }
        }

        // Faz requisição RDAP
        let url = format!("https://rdap.org/domain/{}", cache_key);
        let resp = self.client.get(&url).send().ok()?;
        
        if !resp.status().is_success() {
            return None;
        }

        let rdap: RdapResponse = resp.json().ok()?;
        let age = self.calculate_age_days(&rdap);

        // Atualiza cache
        if let Ok(mut cache) = self.cache.lock() {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis() as u64;
            cache.insert(cache_key, CachedRdap { data: rdap, cached_at: now });
        }

        age
    }

    fn calculate_age_days(&self, rdap: &RdapResponse) -> Option<u32> {
        // Procura evento de registro
        let reg_event = rdap.events.iter().find(|e| e.event_action == "registration")?;
        
        // Parse da data ISO 8601
        let reg_date = DateTime::parse_from_rfc3339(&reg_event.event_date).ok()?;
        let now = Utc::now();
        
        let diff = now.signed_duration_since(reg_date.with_timezone(&Utc));
        Some(diff.num_days().max(0) as u32)
    }

    /// Obtém registrar do domínio (para análise de reputação)
    pub fn get_registrar(&self, domain: &str) -> Option<String> {
        let cache_key = domain.to_lowercase();
        
        if let Ok(cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&cache_key) {
                return self.extract_registrar(&cached.data);
            }
        }

        let url = format!("https://rdap.org/domain/{}", cache_key);
        let resp = self.client.get(&url).send().ok()?;
        let rdap: RdapResponse = resp.json().ok()?;
        
        if let Ok(mut cache) = self.cache.lock() {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis() as u64;
            cache.insert(cache_key, CachedRdap { data: rdap.clone(), cached_at: now });
        }

        self.extract_registrar(&rdap)
    }

    fn extract_registrar(&self, rdap: &RdapResponse) -> Option<String> {
        rdap.entities.as_ref()?.iter()
            .find(|e| e.roles.contains(&"registrar".to_string()))?
            .vcard_array.as_ref()?.get(1)?.as_array()?
            .iter()
            .find(|v| v[0].as_str() == Some("fn"))?
            [3].as_str()
            .map(|s| s.to_string())
    }

    /// Verifica se domínio está ativo (não expirado)
    pub fn is_domain_active(&self, domain: &str) -> Option<bool> {
        let cache_key = domain.to_lowercase();
        
        let rdap = if let Ok(cache) = self.cache.lock() {
            cache.get(&cache_key).map(|c| c.data.clone())
        } else {
            None
        };

        let rdap = rdap.or_else(|| {
            let url = format!("https://rdap.org/domain/{}", cache_key);
            self.client.get(&url).send().ok()?.json().ok()
        })?;

        // Verifica status
        if let Some(status) = &rdap.status {
            if status.iter().any(|s| s.contains("inactive") || s.contains("expired")) {
                return Some(false);
            }
        }

        // Verifica data de expiração
        for event in &rdap.events {
            if event.event_action == "expiration" {
                if let Ok(exp_date) = DateTime::parse_from_rfc3339(&event.event_date) {
                    return Some(Utc::now() < exp_date.with_timezone(&Utc));
                }
            }
        }

        Some(true) // Assume ativo se não há info de expiração
    }
}

/// Instância global singleton (inicializada lazy)
static RDAP_CLIENT: std::sync::OnceLock<RdapClient> = std::sync::OnceLock::new();

pub fn get_rdap_client(timeout_ms: u64) -> &'static RdapClient {
    RDAP_CLIENT.get_or_init(|| RdapClient::new(timeout_ms))
}

/// Função de conveniência para idade do domínio
pub fn get_domain_age_days(domain: &str, timeout_ms: u64) -> Option<u32> {
    get_rdap_client(timeout_ms).get_domain_age_days(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdap_known_domain() {
        // Testa com domínio conhecido antigo
        let age = get_domain_age_days("google.com", 5000);
        assert!(age.is_some());
        assert!(age.unwrap() > 365 * 20); // Google tem mais de 20 anos
    }

    #[test]
    fn test_rdap_cache() {
        let client = RdapClient::new(5000);
        let age1 = client.get_domain_age_days("github.com");
        let age2 = client.get_domain_age_days("github.com");
        assert_eq!(age1, age2); // Deve vir do cache na segunda chamada
    }
}