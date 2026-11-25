//! Filtro Bloom para verificação offline de blocklists
//! 
//! Carrega listas compiladas (OISD, HaGeZi, URLhaus, PhishStats) em um Bloom filter
//! compacto (< 5 MB) para verificação instantânea sem rede.

use crate::types::*;
use bloomfilter::Bloom;
use std::fs;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use anyhow::{Result, Context, anyhow};
use serde::{Serialize, Deserialize};

/// Tamanho padrão do Bloom filter (bits) - ~1M entradas com taxa de falso positivo ~1%
const DEFAULT_BITMAP_SIZE: usize = 10_000_000; // ~1.25 MB
const DEFAULT_ITEMS_COUNT: usize = 1_000_000;

/// Estrutura do filtro Bloom serializável
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistBloom {
    /// Dados do filtro codificados em base64
    pub filter_data: String,
    /// Número de bits
    pub size: usize,
    /// Número de funções hash
    pub hash_funcs: usize,
    /// Número estimado de entradas
    pub estimated_entries: usize,
    /// Timestamp de geração (UNIX epoch ms)
    pub generated_at_ms: i64,
    /// Versão do formato
    pub version: u32,
    /// Fontes incluídas
    pub sources: Vec<String>,
}

impl BlocklistBloom {
    /// Cria novo filtro vazio
    pub fn new(estimated_entries: usize) -> Result<Self> {
        let items = estimated_entries.max(DEFAULT_ITEMS_COUNT);
        let size = (items * 10).max(DEFAULT_BITMAP_SIZE); // 10 bits por entrada
        
        let bloom = Bloom::<[u8]>::new(size, items).map_err(|e| anyhow!("Falha ao criar Bloom filter: {}", e))?;
        
        let filter_bytes = bloom.to_bytes();
        Ok(Self {
            filter_data: BASE64.encode(filter_bytes),
            size: bloom.len() as usize,
            hash_funcs: bloom.number_of_hash_functions() as usize,
            estimated_entries: items,
            generated_at_ms: chrono::Utc::now().timestamp_millis(),
            version: 1,
            sources: Vec::new(),
        })
    }

    /// Carrega filtro de arquivo JSON
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let bloom: BlocklistBloom = serde_json::from_str(&content)?;
        Ok(bloom)
    }

    /// Salva filtro em arquivo JSON
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Cria instância Bloom do filtro armazenado
    fn get_bloom(&self) -> Result<Bloom<[u8]>> {
        let bloom_bytes = BASE64.decode(&self.filter_data)?;
        Bloom::from_bytes(bloom_bytes).map_err(|e| anyhow!("Falha ao deserializar Bloom filter: {}", e))
    }

    /// Verifica se um domínio está na blocklist
    pub fn contains(&self, domain: &str) -> bool {
        self.get_bloom()
            .map(|b| b.check(domain.as_bytes()))
            .unwrap_or(false)
    }

    /// Verifica domínio e subdomínios (ex.: verifica "sub.evil.com" e "evil.com")
    pub fn contains_domain_or_parent(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let parts: Vec<&str> = domain.split('.').collect();
        
        // Verifica domínio completo e todos os pais
        for i in 0..parts.len() {
            let parent = parts[i..].join(".");
            if self.contains(&parent) {
                return true;
            }
        }
        false
    }
}

/// Builder para compilar blocklists em Bloom filter
pub struct BloomBuilder {
    bloom: Bloom<[u8]>,
    sources: Vec<String>,
    total_entries: usize,
}

impl BloomBuilder {
    pub fn new(estimated_total: usize) -> Result<Self> {
        let items = estimated_total.max(DEFAULT_ITEMS_COUNT);
        let size = (items * 10).max(DEFAULT_BITMAP_SIZE);
        
        Ok(Self {
            bloom: Bloom::<[u8]>::new(size, items).map_err(|e| anyhow!("Falha ao criar Bloom filter: {}", e))?,
            sources: Vec::new(),
            total_entries: 0,
        })
    }

    /// Adiciona domínios de um arquivo (uma por linha, formato hosts ou domínio simples)
    pub fn add_file<P: AsRef<Path>>(&mut self, path: P, source_name: &str) -> Result<usize> {
        let content = fs::read_to_string(path)?;
        let mut added = 0;
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Formato hosts: "0.0.0.0 domain.com" ou apenas "domain.com"
            let domain = if line.contains(' ') {
                line.split_whitespace().nth(1).unwrap_or(line)
            } else {
                line
            };
            
            let domain = domain.to_lowercase().trim().to_string();
            if domain.is_empty() || domain.contains(':') { // pula IPv6
                continue;
            }
            
            self.bloom.set(domain.as_bytes());
            added += 1;
        }
        
        self.total_entries += added;
        self.sources.push(format!("{} ({} entries)", source_name, added));
        Ok(added)
    }

    /// Adiciona domínios de um vetor
    pub fn add_domains(&mut self, domains: &[String], source_name: &str) {
        for domain in domains {
            self.bloom.set(domain.as_bytes());
        }
        self.total_entries += domains.len();
        self.sources.push(format!("{} ({} entries)", source_name, domains.len()));
    }

    /// Finaliza e gera BlocklistBloom
    pub fn build(self) -> Result<BlocklistBloom> {
        let filter_bytes = self.bloom.to_bytes();
        Ok(BlocklistBloom {
            filter_data: BASE64.encode(filter_bytes),
            size: self.bloom.len() as usize,
            hash_funcs: self.bloom.number_of_hash_functions() as usize,
            estimated_entries: self.total_entries,
            generated_at_ms: chrono::Utc::now().timestamp_millis(),
            version: 1,
            sources: self.sources,
        })
    }
}

/// Verificador de blocklist offline (singleton)
static BLOCKLIST: std::sync::OnceLock<BlocklistBloom> = std::sync::OnceLock::new();

pub fn init_blocklist(bloom: BlocklistBloom) {
    BLOCKLIST.set(bloom).ok();
}

pub fn get_blocklist() -> Option<&'static BlocklistBloom> {
    BLOCKLIST.get()
}

pub fn check_blocklist(domain: &str) -> bool {
    get_blocklist().map(|b| b.contains_domain_or_parent(domain)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_basic() -> Result<()> {
        let mut builder = BloomBuilder::new(1000)?;
        builder.add_domains(&["evil.com".into(), "phish.net".into(), "malware.org".into()], "test");
        let bloom = builder.build()?;
        
        assert!(bloom.contains("evil.com"));
        assert!(bloom.contains("phish.net"));
        assert!(bloom.contains("malware.org"));
        assert!(!bloom.contains("google.com"));
        Ok(())
    }

    #[test]
    fn test_subdomain_check() -> Result<()> {
        let mut builder = BloomBuilder::new(1000)?;
        builder.add_domains(&["evil.com".into()], "test");
        let bloom = builder.build()?;
        
        assert!(bloom.contains_domain_or_parent("evil.com"));
        assert!(bloom.contains_domain_or_parent("sub.evil.com"));
        assert!(bloom.contains_domain_or_parent("deep.sub.evil.com"));
        assert!(!bloom.contains_domain_or_parent("good.com"));
        Ok(())
    }

    #[test]
    fn test_serialization() -> Result<()> {
        let mut builder = BloomBuilder::new(1000)?;
        builder.add_domains(&["test.com".into()], "test");
        let bloom = builder.build()?;
        
        let json = serde_json::to_string(&bloom)?;
        let loaded: BlocklistBloom = serde_json::from_str(&json)?;
        
        assert!(loaded.contains("test.com"));
        assert!(!loaded.contains("other.com"));
        Ok(())
    }
}