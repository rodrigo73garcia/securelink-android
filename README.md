# SecureLink 🔗🛡️

> **Proteção open-source contra phishing, golpes e links maliciosos no Android (iOS em desenvolvimento)**

[![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Kotlin](https://img.shields.io/badge/Kotlin-1.9%2B-purple.svg)](https://kotlinlang.org)
[![Android](https://img.shields.io/badge/Android-API%2024%2B-green.svg)](https://developer.android.com)

---

## 🎯 O problema

Hoje, golpistas criam milhares de sites clones por dia usando técnicas modernas:

- **Homógrafos (IDN/Punycode)**: `аpple.com` (com 'а' cirílico) parece `apple.com`
- **Typosquatting**: `cacaushowbr.com` imitando `cacaushow.com.br`
- **Combosquatting**: `cacaushow-promo.com`, `nubank-login.xyz`
- **Subdomain trick**: `cacaushow.com.br.evil.com` (o domínio real é `evil.com`)
- **Domínios novos**: Registrados há horas/dias, não estão em blocklists tradicionais

Usuários leigos (e até técnicos) clicam no link achando que é o site oficial e caem no golpe.

---

## ✨ Solução: SecureLink

**Intercepta o clique ANTES de abrir o navegador** e analisa o link em milissegundos:

```
Link clicado → SecureLink (navegador padrão) → Análise offline + RDAP → Veredito
                                                      ↓
                                            ✅ Seguro → Abre no Chrome
                                            ⚠️ Suspeito → Mostra motivos, usuário decide
                                            🚫 PERIGO → Bloqueia, mostra site oficial
```

### 🛡️ Camadas de proteção (todas offline, exceto RDAP opcional)

| Camada | O que detecta | Tempo |
|--------|--------------|-------|
| **Bloom Filter** | 1M+ domínios de phishing/malware (OISD, HaGeZi, URLhaus, PhishStats) | < 1ms |
| **Homógrafos** | Cirílico, grego, mistura de alfabetos, Punycode (`xn--`) | < 1ms |
| **Typosquatting** | Distância de edição vs 400+ marcas (foco Brasil) | < 2ms |
| **Combosquatting** | Marca + palavras suspeitas (`promo`, `login`, `pix`, `urgente`) | < 2ms |
| **Subdomain trick** | Marca no subdomínio, domínio real diferente | < 1ms |
| **Idade do domínio** | RDAP: domínios < 7 dias = crítico, < 30 dias = alerta | ~100ms |
| **Heurísticas URL** | Encurtadores, TLDs abusados, IP como host, paths profundos | < 1ms |
| **VirusTotal** | (Opcional) Chave própria do usuário | ~2s |

---

## 📱 Como funciona no Android

1. **Instala o app** (F-Droid, GitHub Releases, ou Play Store)
2. **Define como navegador padrão** (Configurações → Apps → Navegador padrão → SecureLink)
3. **Pronto!** Todo link clicado no WhatsApp, Telegram, SMS, Email, Chrome passa pelo SecureLink primeiro

### 🔄 Para links em WebViews internas (Instagram, Facebook, TikTok)
- Use **Compartilhar → SecureLink** ou adicione o atalho na tela inicial
- Futuro: VPN local opcional (estilo RethinkDNS) para cobrir 100%

---

## 🏗️ Arquitetura

```
securelink-android/
├── core/                    # 🦀 Rust - Motor de detecção (compartilhável iOS)
│   ├── idn_homograph/       # Detecção homógrafos/Punycode (Unicode UTS#39)
│   ├── typosquatting/       # Levenshtein/Jaro-Winkler + leet speak
│   ├── rdap/                # Consulta idade domínio (RDAP.org)
│   ├── bloom/               # Bloom filter offline blocklists
│   ├── scorer/              # Motor de pontuação explicável 0-100
│   └── jni_bindings/        # Bridge JNI para Android
├── android/                 # 🤖 App Kotlin
│   ├── app/                 # MainActivity (navegador padrão)
│   ├── ShareTargetActivity  # Recebe links via "Compartilhar"
│   ├── BlocklistUpdateWorker# Atualização diária automática
│   └── Preferences          # DataStore + Hilt DI
├── blocklist-builder/       # 🔨 CLI Rust para gerar .bloom diário
└── .github/workflows/       # CI/CD + blocklist diária automatizada
```

---

## 🚀 Build Local

### Pré-requisitos
- Rust 1.75+ (`rustup default stable`)
- Android SDK + NDK 26 (`ANDROID_NDK_HOME`)
- JDK 17
- `cargo install cargo-ndk` (opcional)

### Compilar core Rust para Android
```bash
cd core
# Adiciona targets Android
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Define linkers (ajuste ANDROID_NDK_HOME)
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi24-clang
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android24-clang
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android24-clang

# Compila
cargo build --target aarch64-linux-android --release --features android
# ... repita para outros targets

# Copia .so para android/app/src/main/jniLibs/<abi>/
```

### Build do APK
```bash
cd android
./gradlew assembleDebug
# APK em app/build/outputs/apk/debug/app-debug.apk
```

### Gerar blocklist local
```bash
cd blocklist-builder
cargo build --release
./target/release/blocklist-builder \
  --inputs ../blocklists/*.txt \
  --output ../android/app/src/main/assets/blocklist.bloom \
  --version $(date +%s)
```

---

## 🧪 Testes

```bash
# Testes unitários Rust
cd core && cargo test

# Testes unitários Android
cd android && ./gradlew testDebugUnitTest

# Exemplo de detecção homógrafa
cargo test --test homograph_cyrillic
```

---

## 📊 Marcas monitoradas (Brasil + Global)

O arquivo [`android/app/src/main/assets/brands/br.json`](android/app/src/main/assets/brands/br.json) contém **60+ marcas** com prioridade:

**Bancos/Pagamentos**: Nubank, Itaú, BB, Bradesco, Santander, Caixa, Inter, C6, Next, PicPay, Mercado Pago, PagSeguro, PayPal
**E-commerce**: Mercado Livre, Magalu, Amazon, Americanas, Shopee, Shein, AliExpress
**Governo**: Gov.br, Receita Federal, INSS, Correios, Detran
**Tech/Redes**: Google, Microsoft, Apple, WhatsApp, Telegram, Instagram, Facebook, Twitter/X, Discord, LinkedIn, TikTok
**Streaming**: Netflix, Spotify, Disney+, HBO Max, Prime Video, Globoplay
**Jogos**: Steam, Epic Games, PlayStation, Xbox, Battle.net
**Dev/Cloud**: GitHub, GitLab, AWS, GCP, Azure, Cloudflare, Vercel, Netlify
**Viagens**: Decolar, Gol, LATAM, Azul, Booking, Airbnb, 123Milhas

> **Comunitário**: Adicione marcas via PR no `brands/br.json`

---

## 🔒 Privacidade

- **Zero coleta de dados**: Nenhuma URL sai do dispositivo (exceto RDAP opcional e VirusTotal opcional)
- **Sem conta, sem login, sem telemetria**
- **Código 100% auditável**: Rust + Kotlin open source
- **Blocklists atualizadas via GitHub Actions** (transparente, sem servidor próprio)

---

## 📄 Licença

- **Core Rust (`core/`)**: MIT ou Apache-2.0 (para outros projetos de segurança usarem)
- **App Android (`android/`)**: GPL-3.0 (evita forks proprietários fechados)
- **Blocklist-builder**: MIT

---

## 🤝 Contribuindo

1. Fork o repo
2. Crie branch: `git checkout -b feature/nova-deteccao`
3. Commit: `git commit -m 'feat: adiciona detecção de X'`
4. Push: `git push origin feature/nova-deteccao`
5. Abra Pull Request

### Ideias para contribuir
- 🇧🇷 Mais marcas brasileiras no `brands/br.json`
- 🌐 Suporte a iOS (Safari Extension + NEURLFilter iOS 26+)
- 🤖 Modelo ML leve on-device (TFLite/ONNX) para golpes sem imitação de marca
- 📱 VPN local opcional (estilo RethinkDNS) para WebViews internas
- 🌍 Traduções (PT-BR, EN, ES)

---

## 📞 Contato / Issues

- **Bugs/Features**: [GitHub Issues](https://github.com/seu-usuario/securelink/issues)
- **Segurança**: Reporte vulnerabilidades via `security@seu-dominio.com` (não abra issue público)
- **Discussões**: [GitHub Discussions](https://github.com/seu-usuario/securelink/discussions)

---

## 🙏 Créditos

Inspirado e baseado em projetos open source incríveis:
- [URLCheck](https://github.com/TrianguloY/URLCheck) - Interceptação Android via navegador padrão
- [url.vet](https://github.com/abhizaik/urlvet) - Motor de detecção explicável
- [RethinkDNS](https://github.com/celzero/rethink-dns) - VPN/DNS local Android
- [HaGeZi Blocklists](https://github.com/hagezi/dns-blocklists) - Feeds de phishing/NRD
- [OISD](https://oisd.nl/) - Blocklist consolidada
- [Unicode UTS #39](https://unicode.org/reports/tr39/) - Segurança IDN/homógrafos

---

**Feito com ❤️ para proteger usuários brasileiros contra golpes modernos.**

> *"A melhor defesa contra phishing não é treinar o usuário para não clicar — é fazer o clique seguro por padrão."*