//! Bindings JNI para Android (Kotlin)
//! 
//! Compila como cdylib para libsecurelink_core.so

use crate::types::*;
use crate::scorer::*;
use jni::objects::{JClass, JString, JObjectArray};
use jni::sys::{jint, jlong, jboolean};
use jni::JNIEnv;
use std::os::raw::c_char;

/// Inicializa o motor com configuração JSON
#[no_mangle]
pub extern "system" fn Java_com_securelink_core_SecureLinkEngine_init(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jboolean {
    let config_str: String = env.get_string(&config_json).unwrap().into();
    let config: EngineConfig = match serde_json::from_str(&config_str) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Falha ao parsear config: {}", e);
            return 0;
        }
    };
    
    init_engine(config);
    init_blocklist(BlocklistBloom::new(100_000)); // Será substituído pelo carregado do assets
    
    1
}

/// Carrega Bloom filter de arquivo (assets)
#[no_mangle]
pub extern "system" fn Java_com_securelink_core_SecureLinkEngine_loadBloomFilter(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jboolean {
    let path_str: String = env.get_string(&path).unwrap().into();
    match BlocklistBloom::load_from_file(&path_str) {
        Ok(bloom) => {
            init_blocklist(bloom);
            1
        }
        Err(e) => {
            log::error!("Falha ao carregar Bloom filter: {}", e);
            0
        }
    }
}

/// Analisa URL e retorna resultado como JSON
#[no_mangle]
pub extern "system" fn Java_com_securelink_core_SecureLinkEngine_analyzeUrl(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
) -> JString {
    let url_str: String = env.get_string(&url).unwrap().into();
    
    let result = match analyze_url(&url_str) {
        Some(r) => r,
        None => {
            let error_result = FfiAnalysisResult {
                final_url: url_str.clone(),
                risk_score: 50,
                verdict: Verdict::Suspicious,
                reasons: vec![FfiReason {
                    code: "ENGINE_NOT_INITIALIZED".into(),
                    message_pt: "Motor não inicializado".into(),
                    severity: "WARNING".into(),
                }],
                impersonated_brand: None,
                domain_age_days: None,
                has_homograph: false,
                in_blocklist: false,
            };
            return env.new_string(serde_json::to_string(&error_result).unwrap()).unwrap();
        }
    };
    
    let ffi_result: FfiAnalysisResult = result.into();
    let json = serde_json::to_string(&ffi_result).unwrap_or_else(|_| "{}".into());
    env.new_string(json).unwrap()
}

/// Versão simples que retorna apenas o score (para decisões rápidas)
#[no_mangle]
pub extern "system" fn Java_com_securelink_core_SecureLinkEngine_quickCheck(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
) -> jint {
    let url_str: String = env.get_string(&url).unwrap().into();
    
    match analyze_url(&url_str) {
        Some(result) => result.risk_score as jint,
        None => 50,
    }
}

/// Verifica apenas se está na blocklist (muito rápido)
#[no_mangle]
pub extern "system" fn Java_com_securelink_core_SecureLinkEngine_isBlocklisted(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jboolean {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    check_blocklist(&domain_str) as jboolean
}

/// Obtém idade do domínio via RDAP
#[no_mangle]
pub extern "system" fn Java_com_securelink_core_SecureLinkEngine_getDomainAge(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
) -> jint {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    get_domain_age_days(&domain_str, 5000).unwrap_or(0) as jint
}

/// Expande URL curta
#[no_mangle]
pub extern "system" fn Java_com_securelink_core_SecureLinkEngine_expandUrl(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
) -> JString {
    let url_str: String = env.get_string(&url).unwrap().into();
    let expanded = expand_url(&url_str, 10000);
    env.new_string(expanded).unwrap()
}