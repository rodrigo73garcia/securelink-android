//! Descurtador de URLs (expande bit.ly, tinyurl, t.co, etc.)
//! 
//! Faz requisição HEAD seguindo redirecionamentos sem baixar corpo HTML.

use crate::types::*;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Cliente para descurtar URLs
pub struct Unshortener {
    client: Client,
    timeout_ms: u64,
    max_redirects: usize,
}

impl Unshortener {
    pub fn new(timeout_ms: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .redirect(reqwest::redirect::Policy::limited(20))
            .user_agent("SecureLink/0.1 (+https://github.com/usuario/securelink)")
            .build()
            .expect("Falha ao criar cliente HTTP");

        Self {
            client,
            timeout_ms,
            max_redirects: 20,
        }
    }

    /// Expande URL curta seguindo redirecionamentos
    /// Retorna URL final ou original se falhar
    pub fn expand(&self, url: &str) -> String {
        // Validação básica
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return url.to_string();
        }

        // Lista de encurtadores conhecidos (para log/estatística)
        let shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
            "buff.ly", "adf.ly", "bc.vc", "cutt.ly", "short.io", "rebrand.ly",
            "tiny.cc", "clck.ru", "v.gd", "tr.im", "urlz.fr", "x.co",
            "bit.do", "shorturl.at", "rb.gy", "shrtco.de", "ln.run",
        ];

        let is_known_shortener = shorteners.iter().any(|s| url.contains(s));

        // Faz requisição HEAD (sem corpo)
        match self.client.head(url).send() {
            Ok(resp) => {
                let final_url = resp.url().as_str().to_string();
                if final_url != url {
                    log::info!("URL expandida: {} -> {} (shortener: {})", url, final_url, is_known_shortener);
                }
                final_url
            }
            Err(e) => {
                log::warn!("Falha ao expandir {}: {}", url, e);
                url.to_string()
            }
        }
    }

    /// Expande com detalhes (para debug/log)
    pub fn expand_with_info(&self, url: &str) -> UnshortenResult {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return UnshortenResult {
                original: url.to_string(),
                final_url: url.to_string(),
                redirected: false,
                redirect_count: 0,
                is_shortener: false,
                error: None,
            };
        }

        match self.client.head(url).send() {
            Ok(resp) => {
                let final_url = resp.url().as_str().to_string();
                let redirected = final_url != url;
                UnshortenResult {
                    original: url.to_string(),
                    final_url,
                    redirected,
                    redirect_count: 0, // reqwest não expõe count facilmente
                    is_shortener: false, // TODO: detectar
                    error: None,
                }
            }
            Err(e) => UnshortenResult {
                original: url.to_string(),
                final_url: url.to_string(),
                redirected: false,
                redirect_count: 0,
                is_shortener: false,
                error: Some(e.to_string()),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshortenResult {
    pub original: String,
    pub final_url: String,
    pub redirected: bool,
    pub redirect_count: usize,
    pub is_shortener: bool,
    pub error: Option<String>,
}

/// Instância global
static UNSHORTENER: std::sync::OnceLock<Unshortener> = std::sync::OnceLock::new();

pub fn get_unshortener(timeout_ms: u64) -> &'static Unshortener {
    UNSHORTENER.get_or_init(|| Unshortener::new(timeout_ms))
}

pub fn expand_url(url: &str, timeout_ms: u64) -> String {
    get_unshortener(timeout_ms).expand(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_url_unchanged() {
        let unshortener = Unshortener::new(5000);
        let url = "https://google.com";
        // Não testamos rede real em unit test
        assert_eq!(unshortener.expand("not-a-url"), "not-a-url");
    }
}