use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use bloomfilter::Bloom;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bincode;
use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(name = "blocklist-builder", version, about = "Builds Bloom filter from blocklist sources")]
struct Args {
    /// Arquivos de entrada (um domínio por linha)
    #[arg(short, long, value_delimiter = ' ')]
    inputs: Vec<PathBuf>,

    /// Arquivo de saída .bloom
    #[arg(short, long, default_value = "blocklist.bloom")]
    output: PathBuf,

    /// Versão da blocklist (timestamp UNIX)
    #[arg(short, long)]
    version: Option<u64>,

    /// Tamanho estimado do filtro (bits por entrada * 10)
    #[arg(long, default_value = "10000000")]
    size: usize,

    /// Número de funções hash
    #[arg(long, default_value = "7")]
    hash_funcs: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlocklistBloom {
    filter_data: String,
    size: usize,
    hash_funcs: usize,
    estimated_entries: usize,
    generated_at_ms: i64,
    version: u64,
    sources: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    let version = args.version.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });

    println!("🔨 SecureLink Blocklist Builder v{}", env!("CARGO_PKG_VERSION"));
    println!("📥 Lendo {} arquivo(s) de entrada...", args.inputs.len());

    let mut domains = HashSet::new();
    let mut sources = Vec::new();

    for input_path in &args.inputs {
        let content = fs::read_to_string(input_path)?;
        let mut count = 0;
        
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
            if domain.is_empty() || domain.contains(':') {
                continue;
            }
            
            domains.insert(domain);
            count += 1;
        }
        
        sources.push(format!("{} ({})", input_path.display(), count));
        println!("  ✅ {}: {} domínios", input_path.display(), count);
    }

    println!("📊 Total de domínios únicos: {}", domains.len());

    // Cria Bloom filter
    let bloom = Bloom::new(args.size, args.hash_funcs);
    for domain in &domains {
        bloom.insert(domain.as_bytes());
    }

    // Serializa
    let filter_bytes = bincode::serialize(&bloom)?;
    let filter_b64 = BASE64.encode(filter_bytes);

    let blocklist = BlocklistBloom {
        filter_data: filter_b64,
        size: bloom.size(),
        hash_funcs: bloom.k(),
        estimated_entries: domains.len(),
        generated_at_ms: chrono::Utc::now().timestamp_millis(),
        version,
        sources,
    };

    // Salva
    let json = serde_json::to_string_pretty(&blocklist)?;
    fs::write(&args.output, json)?;

    println!("✅ Bloom filter salvo em: {}", args.output.display());
    println!("   Tamanho: {} bytes", json.len());
    println!("   Entradas estimadas: {}", domains.len());
    println!("   Tamanho do filtro: {} bits ({} MB)", bloom.size(), bloom.size() / 8 / 1024 / 1024);
    println!("   Funções hash: {}", bloom.k());
    println!("   Versão: {}", version);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_build_bloom() {
        let mut input = NamedTempFile::new().unwrap();
        writeln!(input, "evil.com").unwrap();
        writeln!(input, "phish.net").unwrap();
        writeln!(input, "malware.org").unwrap();
        input.flush().unwrap();

        let output = NamedTempFile::new().unwrap();
        let output_path = output.path().to_path_buf();

        // Simula args
        let args = Args {
            inputs: vec![input.path().to_path_buf()],
            output: output_path.clone(),
            version: Some(12345),
            size: 10000,
            hash_funcs: 3,
        };

        // Executa lógica principal
        let mut domains = HashSet::new();
        for path in &args.inputs {
            let content = fs::read_to_string(path).unwrap();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                domains.insert(line.to_lowercase());
            }
        }

        let bloom = Bloom::new(args.size, args.hash_funcs);
        for domain in &domains {
            bloom.insert(domain.as_bytes());
        }

        assert!(bloom.check("evil.com".as_bytes()));
        assert!(bloom.check("phish.net".as_bytes()));
        assert!(bloom.check("malware.org".as_bytes()));
        assert!(!bloom.check("google.com".as_bytes()));
    }
}