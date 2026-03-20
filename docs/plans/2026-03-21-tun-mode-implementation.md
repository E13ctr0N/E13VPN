# TUN Mode Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Добавить режим "Полный VPN" (TUN) через sing-box tun inbound с DNS-защитой, переключаемый через UI toggle.

**Architecture:** `VpnMode` enum в Rust управляет генерацией конфига sing-box (mixed inbound vs tun inbound+DNS). UI добавляет `ModeSelector` компонент с персистенцией в store. wintun.dll копируется в app_data_dir перед запуском TUN.

**Tech Stack:** Rust (tauri v2, tauri-plugin-shell), sing-box TUN, wintun.dll, React/TypeScript, tauri-plugin-store

---

### Task 1: Скачать wintun.dll

**Files:**
- Create: `scripts/get-wintun.ps1`
- Create: `src-tauri/binaries/wintun.dll` (скачивается скриптом)

**Step 1: Создать скрипт загрузки**

Создать `scripts/get-wintun.ps1`:

```powershell
$ErrorActionPreference = "Stop"
$url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$zip = "$PSScriptRoot\wintun.zip"
$out = "$PSScriptRoot\..\src-tauri\binaries"

Write-Host "Скачивание wintun..."
Invoke-WebRequest -Uri $url -OutFile $zip

Write-Host "Распаковка..."
Expand-Archive -Path $zip -DestinationPath "$PSScriptRoot\wintun_tmp" -Force
Copy-Item "$PSScriptRoot\wintun_tmp\wintun\bin\amd64\wintun.dll" "$out\wintun.dll" -Force

Remove-Item $zip -Force
Remove-Item "$PSScriptRoot\wintun_tmp" -Recurse -Force
Write-Host "wintun.dll скопирован в $out"
```

**Step 2: Запустить скрипт**

```powershell
cd X:\1NewProject\VPN\ClientPC
powershell -ExecutionPolicy Bypass -File scripts/get-wintun.ps1
```

Ожидаемый результат: файл `src-tauri/binaries/wintun.dll` появился.

**Step 3: Добавить wintun.dll в .gitignore**

Добавить в `.gitignore` (или создать если нет):
```
src-tauri/binaries/wintun.dll
```

**Step 4: Commit**

```bash
git add scripts/get-wintun.ps1 .gitignore
git commit -m "chore: add wintun download script"
```

---

### Task 2: requestedExecutionLevel в tauri.conf.json

**Files:**
- Modify: `src-tauri/tauri.conf.json`

**Step 1: Добавить секцию windows в bundle**

В `src-tauri/tauri.conf.json` изменить секцию `bundle`:

```json
"bundle": {
  "active": true,
  "targets": "all",
  "externalBin": ["binaries/sing-box"],
  "resources": {
    "binaries/wintun.dll": "."
  },
  "windows": {
    "requestedExecutionLevel": "requireAdministrator"
  },
  "icon": [
    "icons/32x32.png",
    "icons/128x128.png",
    "icons/128x128@2x.png",
    "icons/icon.icns",
    "icons/icon.ico"
  ]
}
```

**Step 2: Проверить cargo check**

```bash
cd src-tauri && cargo check
```

Ожидаемый результат: `Finished` без ошибок.

**Step 3: Commit**

```bash
git add src-tauri/tauri.conf.json
git commit -m "chore: require administrator execution level for TUN support"
```

---

### Task 3: VpnMode enum и TUN конфиг в vpn.rs

**Files:**
- Modify: `src-tauri/src/vpn.rs`

**Step 1: Добавить VpnMode enum**

В начало `src-tauri/src/vpn.rs` после `use std::collections::HashMap;` добавить:

```rust
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
```

**Step 2: Добавить build_dns функцию**

После функции `build_route` добавить:

```rust
/// DNS конфиг для TUN режима — защита от DNS утечек.
/// bypass домены резолвятся напрямую, остальные — через VPN.
fn build_dns(bypass: &[String]) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = Vec::new();

    if !bypass.is_empty() {
        let (_, domains): (Vec<_>, Vec<_>) =
            bypass.iter().partition(|s| is_network_entry(s));
        if !domains.is_empty() {
            rules.push(serde_json::json!({
                "domain_suffix": domains,
                "server": "dns-direct"
            }));
        }
    }

    serde_json::json!({
        "servers": [
            {
                "tag": "dns-vpn",
                "address": "tls://8.8.8.8",
                "detour": "proxy"
            },
            {
                "tag": "dns-direct",
                "address": "223.5.5.5",
                "detour": "direct"
            }
        ],
        "rules": rules,
        "final": "dns-vpn",
        "independent_cache": true
    })
}
```

**Step 3: Обновить generate_singbox_config**

Изменить сигнатуру и тело `generate_singbox_config`:

```rust
pub fn generate_singbox_config(
    p: &VlessParams,
    via_vpn: &[String],
    bypass: &[String],
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
            "auto_route": true,
            "strict_route": true,
            "stack": "mixed"
        }]),
    };

    let mut config = serde_json::json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": inbound,
        "outbounds": [
            outbound,
            { "type": "direct", "tag": "direct" },
            { "type": "block",  "tag": "block"  }
        ],
        "route": build_route(via_vpn, bypass)
    });

    if *mode == VpnMode::Tun {
        config["dns"] = build_dns(bypass);
    }

    config
}
```

**Step 4: cargo check**

```bash
cd src-tauri && cargo check
```

Ожидаемый результат: ошибка в lib.rs — `generate_singbox_config` вызывается без `mode`. Это ожидаемо, исправим в Task 4.

---

### Task 4: Обновить lib.rs — mode параметр и wintun копирование

**Files:**
- Modify: `src-tauri/src/lib.rs`

**Step 1: Добавить mode в VpnState**

Изменить структуру `VpnState`:

```rust
struct VpnState {
    process: Mutex<Option<CommandChild>>,
    mode: Mutex<vpn::VpnMode>,
}
```

**Step 2: Обновить start_vpn**

Полная новая версия функции `start_vpn`:

```rust
#[tauri::command]
async fn start_vpn(
    app: AppHandle,
    state: State<'_, VpnState>,
    uri: String,
    via_vpn: Vec<String>,
    bypass_vpn: Vec<String>,
    mode: String,
) -> Result<(), String> {
    let vpn_mode = vpn::VpnMode::from_str(&mode);

    let params = vpn::parse_vless_uri(&uri)?;

    let config_json =
        serde_json::to_string_pretty(&vpn::generate_singbox_config(
            &params, &via_vpn, &bypass_vpn, &vpn_mode,
        ))
        .map_err(|e| e.to_string())?;

    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    let config_path = data_dir.join("singbox.json");
    std::fs::write(&config_path, &config_json).map_err(|e| e.to_string())?;

    // Копируем wintun.dll в app_data_dir для TUN режима
    if vpn_mode == vpn::VpnMode::Tun {
        let resource_dir = app.path().resource_dir().map_err(|e| e.to_string())?;
        let wintun_src = resource_dir.join("wintun.dll");
        let wintun_dst = data_dir.join("wintun.dll");
        if wintun_src.exists() && !wintun_dst.exists() {
            std::fs::copy(&wintun_src, &wintun_dst).map_err(|e| e.to_string())?;
        }
    }

    {
        let mut guard = state.process.lock().unwrap();
        if let Some(child) = guard.take() {
            let _ = child.kill();
        }
    }

    let config_str = config_path
        .to_str()
        .ok_or("неверный путь к конфигу")?
        .to_string();

    let mut cmd = app
        .shell()
        .sidecar("sing-box")
        .map_err(|e| e.to_string())?
        .args(["run", "-c", &config_str]);

    // В TUN режиме sing-box должен найти wintun.dll рядом с собой
    if vpn_mode == vpn::VpnMode::Tun {
        cmd = cmd.current_dir(&data_dir);
    }

    let (mut receiver, child) = cmd.spawn().map_err(|e| e.to_string())?;

    *state.process.lock().unwrap() = Some(child);
    *state.mode.lock().unwrap() = vpn_mode.clone();

    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        use tauri_plugin_shell::process::CommandEvent;
        while let Some(event) = receiver.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let line = String::from_utf8_lossy(&bytes).trim().to_string();
                    if !line.is_empty() {
                        let _ = app_clone.emit("singbox-log", line);
                    }
                }
                CommandEvent::Terminated(status) => {
                    let msg = format!(
                        "sing-box завершился (код: {})",
                        status.code.map(|c| c.to_string()).unwrap_or("?".into())
                    );
                    let _ = app_clone.emit("singbox-terminated", msg);
                    break;
                }
                _ => {}
            }
        }
    });

    if vpn_mode == vpn::VpnMode::Proxy {
        vpn::set_system_proxy(true)?;
    }

    Ok(())
}
```

**Step 3: Обновить stop_vpn**

```rust
#[tauri::command]
async fn stop_vpn(state: State<'_, VpnState>) -> Result<(), String> {
    let mut guard = state.process.lock().unwrap();
    if let Some(child) = guard.take() {
        child.kill().map_err(|e| e.to_string())?;
    }
    let mode = state.mode.lock().unwrap().clone();
    if mode == vpn::VpnMode::Proxy {
        vpn::set_system_proxy(false)?;
    }
    Ok(())
}
```

**Step 4: Обновить инициализацию VpnState в run()**

```rust
.manage(VpnState {
    process: Mutex::new(None),
    mode: Mutex::new(vpn::VpnMode::Proxy),
})
```

**Step 5: cargo check**

```bash
cd src-tauri && cargo check
```

Ожидаемый результат: `Finished` без ошибок.

**Step 6: Commit**

```bash
git add src-tauri/src/vpn.rs src-tauri/src/lib.rs
git commit -m "feat: add TUN mode support in Rust backend"
```

---

### Task 5: ModeSelector компонент и интеграция во фронтенд

**Files:**
- Modify: `src/components/MainScreen.tsx`

**Step 1: Добавить vpnMode state и персистенцию**

В `MainScreen` добавить новый state после `singboxLog`:

```typescript
const [vpnMode, setVpnMode] = useState<"proxy" | "tun">("proxy");
```

В useEffect загрузки (там где грузятся configs):

```typescript
const savedMode = (await store.get<"proxy" | "tun">("vpn_mode")) ?? "proxy";
setVpnMode(savedMode);
```

В useEffect сохранения (там где сохраняются configs):

```typescript
await store.set("vpn_mode", vpnMode);
```

Добавить `vpnMode` в массив зависимостей второго useEffect:
```typescript
}, [configs, activeId, vpnMode, storeReady]);
```

**Step 2: Добавить компонент ModeSelector**

Добавить в конец файла (перед последней `}`):

```tsx
function ModeSelector({
  mode,
  onChange,
  disabled,
}: {
  mode: "proxy" | "tun";
  onChange: (m: "proxy" | "tun") => void;
  disabled: boolean;
}) {
  const btn = (value: "proxy" | "tun", label: string) => {
    const active = mode === value;
    return (
      <button
        onClick={() => !disabled && onChange(value)}
        disabled={disabled}
        style={{
          flex: 1,
          height: "26px",
          border: "none",
          borderRadius: "var(--radius-sm)",
          background: active ? "var(--color-accent)" : "transparent",
          color: active ? "#0d0d0d" : "var(--color-text-muted)",
          cursor: disabled ? "not-allowed" : "pointer",
          fontSize: "10px",
          letterSpacing: "0.08em",
          fontFamily: "var(--font-mono)",
          fontWeight: active ? 600 : 400,
          transition: "background 0.15s, color 0.15s",
          opacity: disabled ? 0.5 : 1,
        }}
      >
        {label}
      </button>
    );
  };

  return (
    <div
      style={{
        display: "flex",
        gap: "3px",
        padding: "6px 14px",
        borderBottom: "1px solid var(--color-border)",
        background: "var(--color-surface)",
        flexShrink: 0,
      }}
    >
      {btn("proxy", "Proxy VPN")}
      {btn("tun", "Полный VPN")}
    </div>
  );
}
```

**Step 3: Вставить ModeSelector в JSX MainScreen**

В `return` компонента `MainScreen`, между `{/* Status bar */}` и `{/* Config list */}`:

```tsx
{/* Mode selector */}
<ModeSelector
  mode={vpnMode}
  onChange={setVpnMode}
  disabled={connected || busy}
/>
```

**Step 4: Передать mode в start_vpn invoke**

В `toggleConnect`, изменить вызов `invoke`:

```typescript
await invoke("start_vpn", { uri: cfg.uri, viaVpn, bypassVpn, mode: vpnMode });
```

**Step 5: npm run build**

```bash
cd X:\1NewProject\VPN\ClientPC && npm run build
```

Ожидаемый результат: `dist/` собрался без ошибок TypeScript.

**Step 6: Commit**

```bash
git add src/components/MainScreen.tsx
git commit -m "feat: add mode selector UI (Proxy VPN / Полный VPN)"
```

---

### Task 6: Финальная проверка сборки

**Step 1: cargo check финальный**

```bash
cd src-tauri && cargo check
```

Ожидаемый результат: `Finished` без ошибок.

**Step 2: Запустить приложение от администратора**

Открыть терминал **от Administrator**, затем:

```bash
cd X:\1NewProject\VPN\ClientPC
npm run tauri dev
```

**Step 3: Проверить Proxy VPN**

1. Выбрать конфиг из списка
2. Убедиться что выбран режим "Proxy VPN"
3. Нажать "Подключить"
4. Открыть Chrome → проверить IP (2ip.ru или similar)
5. Убедиться что IP сменился

**Step 4: Проверить Полный VPN**

1. Отключиться
2. Переключить на "Полный VPN"
3. Нажать "Подключить"
4. Открыть любой браузер (в т.ч. Firefox) → проверить IP
5. Открыть Telegram — должен работать через VPN

**Step 5: Commit если всё ок**

```bash
git add -A
git commit -m "feat: TUN mode (Полный VPN) fully implemented"
```

---

## Примечания

- `wintun.dll` в dev режиме ищется через `resource_dir()` — в Tauri dev это `src-tauri/`. Если не находит — sing-box упадёт с ошибкой в лог (видно в UI). В этом случае скопировать вручную: `src-tauri/wintun.dll`.
- В `cargo tauri dev` UAC manifest не применяется — нужно запускать терминал от Administrator вручную.
- Если sing-box в TUN режиме падает сразу — смотреть строку лога в нижней части UI (добавлено в предыдущей сессии).
