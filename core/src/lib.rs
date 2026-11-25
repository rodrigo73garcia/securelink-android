//! SecureLink Core - Motor de detecção de phishing/homógrafos/typosquatting
//! 
//! Funciona 100% offline (exceto RDAP e descurtador opcionais).
//! Projetado para ser embutido no Android via JNI e no iOS via FFI.

pub mod idn_homograph;
pub mod typosquatting;
pub mod rdap;
pub mod bloom;
pub mod scorer;
pub mod unshortener;
pub mod types;

#[cfg(feature = "android")]
pub mod jni_bindings;

pub use types::*;
pub use idn_homograph::*;
pub use typosquatting::*;
pub use rdap::*;
pub use bloom::*;
pub use scorer::*;
pub use unshortener::*;

use std::sync::OnceLock;

/// Inicialização global (chamada uma vez no startup do app)
pub fn init() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        env_logger::init();
        log::info!("SecureLink Core inicializado");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }
}