# Дизайн: TUN режим ("Полный VPN")

## Контекст

Приложение поддерживает режим системного прокси ("Proxy VPN"). Добавляем TUN режим ("Полный VPN") — перехват всего трафика на уровне IP через виртуальный адаптер, как в nekoray.

## Решения

- **Права:** `requestedExecutionLevel = requireAdministrator` — UAC при каждом запуске
- **wintun.dll:** в `src-tauri/binaries/`, копируется в `app_data_dir` перед запуском TUN
- **UI:** radio toggle над кнопкой подключения, персистируется в store
- **Маршруты:** те же правила "Через VPN" / "Мимо VPN" работают в обоих режимах
- **DNS:** в TUN режиме sing-box перехватывает DNS, резолвит через VPN (защита от утечек)

## Архитектура

### Режимы

```
Proxy VPN:
  inbound: mixed (127.0.0.1:2080)
  → set_system_proxy(true) после запуска
  → set_system_proxy(false) при остановке

Полный VPN (TUN):
  inbound: tun (172.18.0.1/30, auto_route=true, strict_route=true)
  + DNS сервер внутри sing-box
  → системный прокси не трогается
```

### sing-box конфиг TUN

```json
{
  "inbounds": [{
    "type": "tun",
    "tag": "tun-in",
    "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
    "auto_route": true,
    "strict_route": true,
    "stack": "mixed"
  }],
  "dns": {
    "servers": [
      { "tag": "dns-vpn",    "address": "tls://8.8.8.8", "detour": "proxy" },
      { "tag": "dns-direct", "address": "223.5.5.5",     "detour": "direct" }
    ],
    "rules": [
      { "outbound": "direct", "server": "dns-direct" }
    ],
    "final": "dns-vpn"
  }
}
```

DNS-правила зеркалируют route bypass: домены из "Мимо VPN" резолвятся напрямую, остальные — через VPN.

## Изменения по компонентам

### `src-tauri/Cargo.toml`
Без изменений.

### `src-tauri/tauri.conf.json`
```json
"bundle": {
  "windows": { "requestedExecutionLevel": "requireAdministrator" },
  "externalBin": ["binaries/sing-box"],
  "resources": { "binaries/wintun.dll": "." }
}
```

### `src-tauri/src/vpn.rs`
- Добавить `pub enum VpnMode { Proxy, Tun }`
- `generate_singbox_config(p, via_vpn, bypass, mode)` — в TUN добавляет tun inbound и DNS блок вместо mixed inbound
- `set_system_proxy` — без изменений (вызывается только в Proxy режиме)

### `src-tauri/src/lib.rs`
- `VpnState` добавить `mode: Mutex<Option<VpnMode>>` — для корректного stop_vpn
- `start_vpn` принимает `mode: String`
- В TUN режиме: скопировать wintun.dll в app_data_dir, запустить sing-box с `current_dir(app_data_dir)`
- `stop_vpn`: если mode был Proxy — `set_system_proxy(false)`, если TUN — ничего не делаем

### `src/components/MainScreen.tsx`
- Новый компонент `ModeSelector` (два сегмента: "Proxy VPN" / "Полный VPN")
- Состояние `vpnMode` персистируется в store (`vpn_mode`)
- `toggleConnect` передаёт mode в `invoke("start_vpn", { ..., mode })`

### `src-tauri/binaries/`
- Скачать `wintun.dll` скриптом `scripts/get-wintun.ps1`

## UI

```
┌─────────────────────────────┐
│ ● отключено                 │  StatusBar
├─────────────────────────────┤
│  [Proxy VPN] [Полный VPN]  │  ModeSelector (новый)
├─────────────────────────────┤
│  список конфигов            │
├─────────────────────────────┤
│ [+ Добавить] [ПОДКЛЮЧИТЬ]   │  BottomBar
└─────────────────────────────┘
```

Toggle: два сегмента в стиле существующего TabBar, цвет акцента `--color-accent`.

## Примечания

- В `cargo tauri dev` запускать терминал от Administrator (UAC manifest не применяется в dev)
- wintun.dll не включается в git (добавить в .gitignore), скачивается скриптом
- sing-box v1.13.3 уже поддерживает TUN на Windows с wintun
