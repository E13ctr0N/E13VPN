use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum VpnMode {
    Proxy,
    Tun,
}

impl VpnMode {
    pub fn from_str(s: &str) -> Self {
        if s == "tun" { VpnMode::Tun } else { VpnMode::Proxy }
    }
}

#[derive(Debug, Clone)]
pub struct VlessParams {
    pub uuid: String,
    pub host: String,
    pub port: u16,
    pub security: String,
    pub sni: String,
    pub fingerprint: String,
    pub public_key: String,
    pub short_id: String,
    pub flow: String,
    #[allow(dead_code)]
    pub name: String,
}

fn percent_decode(s: &str) -> String {
    let mut buf: Vec<u8> = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    buf.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        buf.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// sing-box поддерживает только "xtls-rprx-vision"; варианты вроде
/// "xtls-rprx-vision-udp443" встречаются в URI, но sing-box их не принимает.
fn normalize_flow(raw: &str) -> String {
    let s = raw.trim();
    if s.starts_with("xtls-rprx-vision") {
        return "xtls-rprx-vision".to_string();
    }
    s.to_string()
}

/// Проверяет формат UUID (8-4-4-4-12 hex)
fn is_valid_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts.iter().zip(expected_lens.iter()).all(|(part, &len)| {
        part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit())
    })
}

/// Допустимые значения параметра security
const ALLOWED_SECURITY: &[&str] = &["reality", "tls", "none", ""];

/// Допустимые значения параметра flow (после нормализации)
const ALLOWED_FLOW: &[&str] = &["", "xtls-rprx-vision"];

pub fn parse_vless_uri(uri: &str) -> Result<VlessParams, String> {
    let uri = uri.trim();

    // Проверка максимальной длины (защита от DoS)
    if uri.len() > 10240 {
        return Err("URI слишком длинный (макс. 10 КБ)".into());
    }

    if !uri.starts_with("vless://") {
        return Err("не является vless:// URI".into());
    }
    let s = &uri[8..]; // strip scheme

    // Fragment (name)
    let (s, name) = if let Some(idx) = s.rfind('#') {
        (&s[..idx], percent_decode(&s[idx + 1..]))
    } else {
        (s, "без имени".into())
    };

    // UUID @ host:port ? query
    let (uuid, rest) = s
        .split_once('@')
        .ok_or("неверный формат: нет @")?;

    // Валидация UUID
    if !is_valid_uuid(uuid) {
        return Err(format!(
            "неверный UUID: ожидается формат xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, получено: {}",
            if uuid.len() > 50 { &uuid[..50] } else { uuid }
        ));
    }

    let (hostport, query) = if let Some(idx) = rest.find('?') {
        (&rest[..idx], &rest[idx + 1..])
    } else {
        (rest, "")
    };

    // host:port — берём последний ":" чтобы обработать IPv6
    let (host, port_s) = hostport
        .rsplit_once(':')
        .ok_or("неверный формат: нет порта")?;
    let port = port_s
        .parse::<u16>()
        .map_err(|_| format!("неверный порт: {port_s}"))?;

    // Порт 0 недопустим
    if port == 0 {
        return Err("порт не может быть 0".into());
    }

    // Валидация host: должен быть IP-адрес или валидный домен
    let clean_host = host.trim_matches(|c| c == '[' || c == ']'); // IPv6 brackets
    if clean_host.parse::<IpAddr>().is_err() && !is_valid_domain(clean_host) {
        return Err(format!("неверный хост: '{}'", if host.len() > 100 { &host[..100] } else { host }));
    }

    let params: HashMap<&str, &str> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .collect();

    let security = params.get("security").unwrap_or(&"none").to_string();
    if !ALLOWED_SECURITY.contains(&security.as_str()) {
        return Err(format!(
            "неподдерживаемое значение security: '{}' (допустимо: reality, tls, none)",
            security
        ));
    }

    let flow = normalize_flow(params.get("flow").unwrap_or(&""));
    if !ALLOWED_FLOW.contains(&flow.as_str()) {
        return Err(format!(
            "неподдерживаемое значение flow: '{}' (допустимо: пусто, xtls-rprx-vision)",
            flow
        ));
    }

    Ok(VlessParams {
        uuid: uuid.to_string(),
        host: host.to_string(),
        port,
        security,
        sni: params.get("sni").unwrap_or(&"").to_string(),
        fingerprint: params.get("fp").unwrap_or(&"chrome").to_string(),
        public_key: params.get("pbk").unwrap_or(&"").to_string(),
        short_id: params.get("sid").unwrap_or(&"").to_string(),
        flow,
        name,
    })
}

/// Запись — сетевой адрес (CIDR или IP) или доменное имя
fn is_network_entry(s: &str) -> bool {
    // CIDR notation (e.g. 10.0.0.0/8, 2001:db8::/32)
    if let Some(slash) = s.find('/') {
        return s[..slash].parse::<IpAddr>().is_ok();
    }
    // Bare IP address
    s.parse::<IpAddr>().is_ok()
}

/// Валидация доменного имени по RFC 1035
fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let s = s.strip_suffix('.').unwrap_or(s);
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Нормализация записи маршрута: извлекает домен из URL, убирает trailing slash/пробелы
fn normalize_entry(s: &str) -> String {
    let s = s.trim();
    // Если пользователь вставил URL вида https://example.com/path — извлекаем хост
    if let Some(rest) = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")) {
        let host = rest.split('/').next().unwrap_or(rest);
        // Убираем порт если есть
        let host = host.split(':').next().unwrap_or(host);
        return host.to_lowercase();
    }
    s.trim_end_matches('/').to_lowercase()
}

/// Строит sing-box route rules.
/// bypass      — домены/IP мимо VPN (direct)
/// bypass_apps — процессы мимо VPN (direct)
/// Всё остальное идёт через proxy (final=proxy).
fn build_route(
    bypass: &[String],
    bypass_apps: &[String],
    mode: &VpnMode,
) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = Vec::new();

    // В TUN-режиме sing-box 1.13 требует sniff и hijack-dns как route rules
    if *mode == VpnMode::Tun {
        rules.push(serde_json::json!({ "action": "sniff" }));
        rules.push(serde_json::json!({ "protocol": "dns", "action": "hijack-dns" }));
    }

    // bypass sites → direct (с валидацией доменов по RFC 1035)
    let norm_bypass: Vec<String> = bypass.iter().map(|s| normalize_entry(s)).collect();
    if !norm_bypass.is_empty() {
        let (nets, domains): (Vec<_>, Vec<_>) =
            norm_bypass.iter().partition(|s| is_network_entry(s));
        let valid_domains: Vec<_> = domains
            .into_iter()
            .filter(|d| is_valid_domain(d))
            .collect();
        if !valid_domains.is_empty() {
            rules.push(serde_json::json!({ "outbound": "direct", "domain_suffix": valid_domains }));
        }
        if !nets.is_empty() {
            rules.push(serde_json::json!({ "outbound": "direct", "ip_cidr": nets }));
        }
    }

    // bypass apps → direct (process_name)
    let norm_apps: Vec<String> = bypass_apps.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !norm_apps.is_empty() {
        rules.push(serde_json::json!({ "outbound": "direct", "process_name": norm_apps }));
    }

    if *mode == VpnMode::Tun {
        rules.push(serde_json::json!({ "ip_cidr": ["1.1.1.1/32"], "outbound": "direct" }));
        rules.push(serde_json::json!({ "ip_is_private": true, "outbound": "direct" }));
    }

    serde_json::json!({
        "rules": rules,
        "final": "proxy",
        "auto_detect_interface": true,
        "default_domain_resolver": "dns-direct"
    })
}

/// DNS конфиг. В TUN — полный с bypass-правилами, в Proxy — минимальный для резолва.
fn build_dns(bypass: &[String], mode: &VpnMode) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = Vec::new();

    if *mode == VpnMode::Tun && !bypass.is_empty() {
        let norm: Vec<String> = bypass.iter().map(|s| normalize_entry(s)).collect();
        let (_, domains): (Vec<_>, Vec<_>) =
            norm.iter().partition(|s| is_network_entry(s));
        let valid_domains: Vec<_> = domains
            .into_iter()
            .filter(|d| is_valid_domain(d))
            .collect();
        if !valid_domains.is_empty() {
            rules.push(serde_json::json!({
                "domain_suffix": valid_domains,
                "server": "dns-direct"
            }));
        }
    }

    // dns-vpn: через VPN (8.8.8.8 через proxy outbound)
    // dns-direct: UDP 1.1.1.1 без detour — трафик к 1.1.1.1 исключён из TUN
    // через route_exclude_address и route rule → direct outbound.
    // detour: "direct" нельзя (sing-box 1.13: "empty direct outbound"),
    // type: "local" нельзя (петля: system DNS → TUN → sing-box → system DNS).
    serde_json::json!({
        "servers": [
            {
                "type": "udp",
                "tag": "dns-vpn",
                "server": "8.8.8.8",
                "server_port": 53,
                "detour": "proxy"
            },
            {
                "type": "udp",
                "tag": "dns-direct",
                "server": "1.1.1.1",
                "server_port": 53
            }
        ],
        "rules": rules,
        "strategy": "ipv4_only",
        "final": "dns-vpn",
        "independent_cache": true
    })
}

pub fn generate_singbox_config(
    p: &VlessParams,
    bypass: &[String],
    bypass_apps: &[String],
    mode: &VpnMode,
) -> serde_json::Value {
    let tls = match p.security.as_str() {
        "reality" => serde_json::json!({
            "enabled": true,
            "server_name": p.sni,
            "utls": { "enabled": true, "fingerprint": p.fingerprint },
            "reality": {
                "enabled": true,
                "public_key": p.public_key,
                "short_id": p.short_id
            }
        }),
        "tls" => serde_json::json!({
            "enabled": true,
            "server_name": p.sni,
            "utls": { "enabled": !p.fingerprint.is_empty(), "fingerprint": p.fingerprint }
        }),
        _ => serde_json::json!({ "enabled": false }),
    };

    let mut outbound = serde_json::json!({
        "type": "vless",
        "tag": "proxy",
        "server": p.host,
        "server_port": p.port,
        "uuid": p.uuid,
        "tls": tls
    });
    if !p.flow.is_empty() {
        outbound["flow"] = serde_json::Value::String(p.flow.clone());
    }
    outbound["packet_encoding"] = serde_json::Value::String("xudp".into());

    let inbound = match mode {
        VpnMode::Proxy => serde_json::json!([{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080
        }]),
        VpnMode::Tun => serde_json::json!([{
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1500,
            "auto_route": true,
            "strict_route": false,
            "stack": "gvisor",
            "route_exclude_address": [
                format!("{}/32", p.host),
                "1.1.1.1/32",
                "2000::/3"
            ]
        }]),
    };

    let config = serde_json::json!({
        "log": { "level": "info", "timestamp": true },
        "dns": build_dns(bypass, mode),
        "inbounds": inbound,
        "outbounds": [
            outbound,
            { "type": "direct", "tag": "direct" }
        ],
        "route": build_route(bypass, bypass_apps, mode),
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090"
            }
        }
    });

    // clash_api в proxy-режиме тоже полезно для индикатора скорости
    config
}

/// HTTP-прокси на 127.0.0.1:2080
pub fn set_system_proxy(enable: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let settings = hkcu
            .open_subkey_with_flags(path, KEY_WRITE)
            .map_err(|e| e.to_string())?;

        if enable {
            settings
                .set_value("ProxyEnable", &1u32)
                .map_err(|e| e.to_string())?;
            settings
                .set_value("ProxyServer", &"127.0.0.1:2080")
                .map_err(|e| e.to_string())?;
        } else {
            settings
                .set_value("ProxyEnable", &0u32)
                .map_err(|e| e.to_string())?;
        }

        // Уведомляем WinINet — без этого Chrome/Edge не подхватывают смену прокси
        unsafe {
            use windows_sys::Win32::Networking::WinInet::{
                InternetSetOptionA, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
            };
            InternetSetOptionA(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
            InternetSetOptionA(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
        }
    }
    Ok(())
}
