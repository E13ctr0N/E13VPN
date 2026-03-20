# UI Improvements Design — 2026-03-22

## Задачи
1. Упрощение маршрутов: убрать "Через VPN", оставить "Мимо VPN (сайты)" + "Мимо VPN (приложения)"
2. Вкладка "Логи" — третья вкладка в TabBar
3. Индикатор скорости — строка статуса внизу главного экрана
4. Убрать debug логи из TUN режима

## 1. Маршруты

### Было
Два столбца: "Через VPN" (via_vpn) и "Мимо VPN" (bypass) — оба принимают домены/IP.

### Станет
Один экран с двумя блоками:
- **Мимо VPN (сайты)** — домены и IP/CIDR → sing-box `domain_suffix` / `ip_cidr`, outbound: direct
- **Мимо VPN (приложения)** — имена процессов (chrome.exe, discord.exe) → sing-box `process_name`, outbound: direct

### Изменения
- Удалить `via_vpn` из UI (RoutesScreen), store, и `generate_singbox_config`
- Добавить `bypass_apps` список в store
- В `build_route()` добавить `process_name` правило
- Placeholder для ввода приложений: "chrome.exe"

## 2. Вкладка "Логи"

### UI
- TabBar: КОНФИГИ | МАРШРУТЫ | ЛОГИ
- Текстовый лог, моноширинный шрифт, автопрокрутка вниз
- Слушает событие `singbox-log` (уже существует в backend)
- Очищается при новом подключении, сохраняется при отключении
- Стиль: фон --color-surface, текст --color-text-muted, ошибки (WARN/ERROR) — --color-danger

### Данные
- Массив строк в state компонента
- Ограничение: последние 1000 строк (чтобы не забивать память)

## 3. Индикатор скорости

### UI
- Строка внизу MainScreen, видна только при активном подключении
- Формат: `↓ 2.4 MB/s  ↑ 0.3 MB/s`
- Стиль: --color-text-muted, мелкий шрифт

### Реализация
- Включить `experimental.clash_api` в sing-box конфиге (порт 9090)
- Фронтенд опрашивает `http://127.0.0.1:9090/traffic` (SSE stream) раз в секунду
- Показывает download/upload speed
- При отключении — скрывается

### sing-box config addition
```json
"experimental": {
  "clash_api": {
    "external_controller": "127.0.0.1:9090"
  }
}
```

## 4. Debug логи
- Убрать условие `if *mode == VpnMode::Tun { "debug" } else { "info" }` → всегда `"info"`
