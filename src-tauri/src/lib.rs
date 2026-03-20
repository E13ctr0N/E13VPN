mod vpn;

use std::sync::Mutex;
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

struct VpnState {
    process: Mutex<Option<CommandChild>>,
    mode: Mutex<vpn::VpnMode>,
}

/// Убить осиротевшие sing-box процессы (если предыдущий запуск крашнулся)
fn kill_orphan_singbox() {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", "sing-box-x86_64-pc-windows-msvc.exe"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output();
    }
}

/// Ждём готовности порта sing-box (TCP connect check)
fn wait_for_port(port: u16, timeout_ms: u64) -> bool {
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    let addr = format!("127.0.0.1:{}", port);
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Очистка VPN-состояния: убить процесс, сбросить прокси
fn cleanup_vpn(state: &VpnState) {
    let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(child) = guard.take() {
        let _ = child.kill();
    }
    let mode = state.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if mode == vpn::VpnMode::Proxy {
        let _ = vpn::set_system_proxy(false);
    }
}

#[tauri::command]
async fn start_vpn(
    app: AppHandle,
    state: State<'_, VpnState>,
    uri: String,
    bypass_vpn: Vec<String>,
    bypass_apps: Vec<String>,
    mode: String,
) -> Result<(), String> {
    let vpn_mode = vpn::VpnMode::from_str(&mode);

    let params = vpn::parse_vless_uri(&uri)?;

    let config_json =
        serde_json::to_string_pretty(&vpn::generate_singbox_config(
            &params, &bypass_vpn, &bypass_apps, &vpn_mode,
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
    // sing-box ищет wintun.dll в CWD, а мы устанавливаем CWD = data_dir
    if vpn_mode == vpn::VpnMode::Tun {
        let wintun_dst = data_dir.join("wintun.dll");
        if !wintun_dst.exists() {
            // Ищем wintun.dll в нескольких местах:
            // 1) resource_dir (tauri resources)
            // 2) resource_dir/binaries (dev mode layout)
            // 3) рядом с exe приложения
            let candidates = {
                let mut c = Vec::new();
                if let Ok(res) = app.path().resource_dir() {
                    c.push(res.join("wintun.dll"));
                    c.push(res.join("binaries").join("wintun.dll"));
                }
                if let Ok(exe) = std::env::current_exe() {
                    if let Some(dir) = exe.parent() {
                        c.push(dir.join("wintun.dll"));
                        c.push(dir.join("binaries").join("wintun.dll"));
                    }
                }
                c
            };
            let found = candidates.iter().find(|p| p.exists());
            if let Some(src) = found {
                std::fs::copy(src, &wintun_dst).map_err(|e| format!("copy wintun.dll: {e}"))?;
            } else {
                return Err("wintun.dll не найден".into());
            }
        }
    }

    // Убиваем предыдущий процесс (из текущей сессии)
    {
        let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(child) = guard.take() {
            let _ = child.kill();
        }
    }

    // Убиваем осиротевшие процессы (из прошлых сессий)
    kill_orphan_singbox();

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

    *state.process.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
    *state.mode.lock().unwrap_or_else(|e| e.into_inner()) = vpn_mode.clone();

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
                    // Автоочистка: сброс прокси при неожиданном завершении
                    if let Some(st) = app_clone.try_state::<VpnState>() {
                        let mode = st.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        if mode == vpn::VpnMode::Proxy {
                            let _ = vpn::set_system_proxy(false);
                        }
                        let _ = st.process.lock().unwrap_or_else(|e| e.into_inner()).take();
                    }
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

    // В proxy-режиме ждём готовности порта перед включением прокси
    if vpn_mode == vpn::VpnMode::Proxy {
        if !wait_for_port(2080, 5000) {
            // sing-box не поднял порт за 5 секунд — откатываемся
            let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(child) = guard.take() {
                let _ = child.kill();
            }
            return Err("sing-box не запустился: порт 2080 недоступен".into());
        }
        vpn::set_system_proxy(true)?;
    }

    Ok(())
}

#[tauri::command]
async fn update_tray_icon(app: AppHandle, connected: bool) -> Result<(), String> {
    let icon_name = if connected { "icons/Tact.png" } else { "icons/Tdis.png" };
    let icon_path = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join(icon_name);
    let image = Image::from_path(&icon_path).map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_icon(Some(image)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn stop_vpn(state: State<'_, VpnState>) -> Result<(), String> {
    let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(child) = guard.take() {
        child.kill().map_err(|e| e.to_string())?;
    }
    let mode = state.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if mode == vpn::VpnMode::Proxy {
        vpn::set_system_proxy(false)?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(VpnState {
            process: Mutex::new(None),
            mode: Mutex::new(vpn::VpnMode::Proxy),
        })
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let show_i = MenuItem::with_id(app, "show", "Показать", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

            let tray_icon_path = app
                .path()
                .resource_dir()
                .map_err(|e| e.to_string())?
                .join("icons/Tdis.png");
            let tray_icon = Image::from_path(&tray_icon_path)
                .map_err(|e| e.to_string())?;

            TrayIconBuilder::with_id("main")
                .menu(&menu)
                .tooltip("E13VPN")
                .icon(tray_icon)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(win) = app.get_webview_window("main") {
                            let _ = win.show();
                            let _ = win.set_focus();
                        }
                    }
                    "quit" => {
                        if let Some(state) = app.try_state::<VpnState>() {
                            cleanup_vpn(state.inner());
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("main") {
                            if win.is_visible().unwrap_or(false) {
                                let _ = win.hide();
                            } else {
                                let _ = win.show();
                                let _ = win.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![start_vpn, stop_vpn, update_tray_icon])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
