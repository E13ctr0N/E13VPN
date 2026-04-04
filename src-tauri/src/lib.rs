mod vpn;

use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

/// Убирает нативную рамку DWM и стили окна (borderless transparent window)
#[cfg(windows)]
fn apply_dwm_borderless(hwnd: windows_sys::Win32::Foundation::HWND) {
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DwmExtendFrameIntoClientArea,
        DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SetWindowLongPtrW, GetWindowLongPtrW, SetWindowPos,
        GWL_STYLE, WS_CAPTION, WS_THICKFRAME, WS_BORDER,
        SWP_FRAMECHANGED, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
    };

    unsafe {
        // Strip all frame styles
        let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
        SetWindowLongPtrW(
            hwnd,
            GWL_STYLE,
            style & !(WS_CAPTION as isize) & !(WS_THICKFRAME as isize) & !(WS_BORDER as isize),
        );

        // Force window to apply new style
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            0, 0, 0, 0,
            SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
        );

        // Zero margins — tell DWM "no frame extension"
        // IMPORTANT: -1 margins cause a white top border on Win10!
        let margins = windows_sys::Win32::UI::Controls::MARGINS {
            cxLeftWidth: 0,
            cxRightWidth: 0,
            cyTopHeight: 0,
            cyBottomHeight: 0,
        };
        DwmExtendFrameIntoClientArea(hwnd, &margins);

        // Rounded corners (Windows 11 only, harmless on Win10)
        let preference = DWMWCP_ROUND;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &preference as *const _ as *const _,
            std::mem::size_of_val(&preference) as u32,
        );
    }
}

/// Subclass proc: перехватывает WM_NCACTIVATE и WM_NCPAINT,
/// чтобы Windows не рисовал артефакты рамки при потере фокуса.
#[cfg(windows)]
unsafe extern "system" fn borderless_subclass_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
    _uid_subclass: usize,
    _ref_data: usize,
) -> isize {
    const WM_NCACTIVATE: u32 = 0x0086;
    const WM_NCPAINT: u32 = 0x0085;

    match msg {
        WM_NCACTIVATE => {
            // Принимаем смену активности, но НЕ передаём DefWindowProc —
            // это предотвращает перерисовку non-client area (белые углы).
            return 1;
        }
        WM_NCPAINT => {
            // Полностью подавляем отрисовку non-client area.
            return 0;
        }
        _ => {}
    }

    windows_sys::Win32::UI::Shell::DefSubclassProc(hwnd, msg, wparam, lparam)
}

/// Устанавливает subclass для перехвата WM_NCACTIVATE/WM_NCPAINT
#[cfg(windows)]
fn install_borderless_subclass(hwnd: windows_sys::Win32::Foundation::HWND) {
    unsafe {
        windows_sys::Win32::UI::Shell::SetWindowSubclass(
            hwnd,
            Some(borderless_subclass_proc),
            1, // subclass ID
            0, // ref data
        );
    }
}

/// SHA256-хеш эталонного sing-box бинарника (v1.13.3, x86_64-pc-windows-msvc)
const EXPECTED_SINGBOX_SHA256: &str =
    "6325205ff2dd0a3046edbad492714621a4f5af80a0a18c915a5976fa07e9c377";

struct VpnState {
    process: Mutex<Option<CommandChild>>,
    mode: Mutex<vpn::VpnMode>,
    last_command: Mutex<Instant>,
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

/// Проверяет SHA256-хеш sing-box бинарника перед запуском
fn verify_singbox_binary(path: &std::path::Path) -> Result<(), String> {
    use sha2::{Sha256, Digest};

    let data = std::fs::read(path)
        .map_err(|e| format!("не удалось прочитать sing-box бинарник: {e}"))?;
    let hash = format!("{:x}", Sha256::digest(&data));

    if hash != EXPECTED_SINGBOX_SHA256 {
        return Err(format!(
            "sing-box не прошёл проверку целостности: ожидался {}, получен {}",
            EXPECTED_SINGBOX_SHA256, hash
        ));
    }
    Ok(())
}

/// Проверяет, запущен ли процесс с правами администратора (Windows)
#[cfg(windows)]
fn is_elevated() -> bool {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::mem::zeroed();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        let _ = windows_sys::Win32::Foundation::CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}

/// Проверяет rate limit: не чаще 1 команды в 500мс
fn check_rate_limit(state: &VpnState) -> Result<(), String> {
    let mut last = state.last_command.lock().unwrap_or_else(|e| e.into_inner());
    if last.elapsed() < Duration::from_millis(500) {
        return Err("слишком частые команды, подождите".into());
    }
    *last = Instant::now();
    Ok(())
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
    check_rate_limit(&state)?;

    let vpn_mode = vpn::VpnMode::from_str(&mode);

    if vpn_mode == vpn::VpnMode::Tun && !is_elevated() {
        return Err("TUN-режим требует запуска от администратора".into());
    }

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

    // SHA256 проверка sing-box перед запуском
    {
        let sidecar_path = app
            .path()
            .resource_dir()
            .map_err(|e| e.to_string())?
            .join("binaries")
            .join("sing-box-x86_64-pc-windows-msvc.exe");
        // Проверяем оба возможных пути: resource/binaries и рядом с exe
        let paths_to_check = {
            let mut v = vec![sidecar_path];
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    v.push(dir.join("sing-box-x86_64-pc-windows-msvc.exe"));
                }
            }
            v
        };
        if let Some(binary_path) = paths_to_check.iter().find(|p| p.exists()) {
            verify_singbox_binary(binary_path)?;
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

    // В proxy-режиме ждём готовности порта перед включением прокси (не блокируя async runtime)
    if vpn_mode == vpn::VpnMode::Proxy {
        let port_ready = tauri::async_runtime::spawn_blocking(|| wait_for_port(2080, 5000))
            .await
            .unwrap_or(false);
        if !port_ready {
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
    check_rate_limit(&state)?;
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

/// Шифрует строку через Windows DPAPI (привязано к пользователю)
#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    use windows_sys::Win32::Foundation::LocalFree;

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };

    let ok = unsafe { CryptProtectData(&mut input, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), 0, &mut output) };
    if ok == 0 {
        return Err("DPAPI CryptProtectData failed".into());
    }
    let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as *mut _) };
    Ok(result)
}

/// Расшифровывает строку через Windows DPAPI
#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    use windows_sys::Win32::Foundation::LocalFree;

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };

    let ok = unsafe { CryptUnprotectData(&mut input, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), 0, &mut output) };
    if ok == 0 {
        return Err("DPAPI CryptUnprotectData failed".into());
    }
    let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as *mut _) };
    Ok(result)
}

#[tauri::command]
fn encrypt_string(value: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        let encrypted = dpapi_protect(value.as_bytes())?;
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
    }
    #[cfg(not(windows))]
    Ok(value)
}

#[tauri::command]
fn update_tray_labels(app: AppHandle, show_label: String, quit_label: String) -> Result<(), String> {
    // Rebuild tray menu with new labels
    let show_i = MenuItem::with_id(&app, "show", &show_label, true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let quit_i = MenuItem::with_id(&app, "quit", &quit_label, true, None::<&str>)
        .map_err(|e| e.to_string())?;
    let menu = Menu::with_items(&app, &[&show_i, &quit_i])
        .map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn decrypt_string(value: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD.decode(&value).map_err(|e| e.to_string())?;
        let decrypted = dpapi_unprotect(&data)?;
        String::from_utf8(decrypted).map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    Ok(value)
}

/// Проверяет, остался ли наш прокси (127.0.0.1:2080) после краша, и сбрасывает его
#[cfg(windows)]
fn cleanup_stale_proxy() {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    if let Ok(settings) = hkcu.open_subkey_with_flags(path, KEY_READ) {
        let enabled: u32 = settings.get_value("ProxyEnable").unwrap_or(0);
        let server: String = settings.get_value("ProxyServer").unwrap_or_default();
        if enabled == 1 && server == "127.0.0.1:2080" {
            // Наш прокси остался — сбрасываем
            let _ = vpn::set_system_proxy(false);
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Сброс прокси если остался после краша
    #[cfg(windows)]
    cleanup_stale_proxy();

    // Panic hook: сбросить прокси при панике
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = vpn::set_system_proxy(false);
        kill_orphan_singbox();
        default_hook(info);
    }));

    tauri::Builder::default()
        .manage(VpnState {
            process: Mutex::new(None),
            mode: Mutex::new(vpn::VpnMode::Proxy),
            last_command: Mutex::new(Instant::now() - Duration::from_secs(1)),
        })
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            // Apply DWM borderless fix + install subclass to prevent white corners on focus loss
            #[cfg(windows)]
            {
                if let Some(win) = app.get_webview_window("main") {
                    let hwnd = win.hwnd().unwrap().0 as windows_sys::Win32::Foundation::HWND;
                    apply_dwm_borderless(hwnd);
                    install_borderless_subclass(hwnd);
                }
            }

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
        .invoke_handler(tauri::generate_handler![start_vpn, stop_vpn, update_tray_icon, encrypt_string, decrypt_string, update_tray_labels])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
