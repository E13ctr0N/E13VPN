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
        let style = GetWindowLongPtrW(hwnd, GWL_STYLE);
        SetWindowLongPtrW(
            hwnd,
            GWL_STYLE,
            style & !(WS_CAPTION as isize) & !(WS_THICKFRAME as isize) & !(WS_BORDER as isize),
        );
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            0, 0, 0, 0,
            SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
        );
        // IMPORTANT: -1 margins cause a white top border on Win10!
        let margins = windows_sys::Win32::UI::Controls::MARGINS {
            cxLeftWidth: 0,
            cxRightWidth: 0,
            cyTopHeight: 0,
            cyBottomHeight: 0,
        };
        DwmExtendFrameIntoClientArea(hwnd, &margins);
        let preference = DWMWCP_ROUND;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &preference as *const _ as *const _,
            std::mem::size_of_val(&preference) as u32,
        );
    }
}

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
        WM_NCACTIVATE => return 1,
        WM_NCPAINT => return 0,
        _ => {}
    }
    windows_sys::Win32::UI::Shell::DefSubclassProc(hwnd, msg, wparam, lparam)
}

#[cfg(windows)]
fn install_borderless_subclass(hwnd: windows_sys::Win32::Foundation::HWND) {
    unsafe {
        windows_sys::Win32::UI::Shell::SetWindowSubclass(hwnd, Some(borderless_subclass_proc), 1, 0);
    }
}

const EXPECTED_SINGBOX_SHA256: &str =
    "6325205ff2dd0a3046edbad492714621a4f5af80a0a18c915a5976fa07e9c377";

struct VpnState {
    process: Mutex<Option<CommandChild>>,
    pid: Mutex<Option<u32>>,
    mode: Mutex<vpn::VpnMode>,
    last_command: Mutex<Instant>,
    last_tun_stop: Mutex<Option<Instant>>,
}

fn kill_orphan_singbox() {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", "sing-box-x86_64-pc-windows-msvc.exe"])
            .creation_flags(0x08000000)
            .output();
        std::thread::sleep(Duration::from_secs(2));
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", "sing-box-x86_64-pc-windows-msvc.exe"])
            .creation_flags(0x08000000)
            .output();
    }
}

fn graceful_kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .creation_flags(0x08000000)
            .output();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(200));
            let check = std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .creation_flags(0x08000000)
                .output();
            if let Ok(out) = check {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.contains("sing-box") {
                    return;
                }
            }
        }
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .creation_flags(0x08000000)
            .output();
    }
}

fn verify_singbox_binary(path: &std::path::Path) -> Result<(), String> {
    use sha2::{Sha256, Digest};
    let data = std::fs::read(path)
        .map_err(|e| format!("sing-box binary read error: {e}"))?;
    let hash = format!("{:x}", Sha256::digest(&data));
    if hash != EXPECTED_SINGBOX_SHA256 {
        return Err(format!("sing-box integrity check failed: expected {}, got {}", EXPECTED_SINGBOX_SHA256, hash));
    }
    Ok(())
}

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
            token, TokenElevation, &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut size,
        );
        let _ = windows_sys::Win32::Foundation::CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool { true }

fn check_rate_limit(state: &VpnState) -> Result<(), String> {
    let mut last = state.last_command.lock().unwrap_or_else(|e| e.into_inner());
    if last.elapsed() < Duration::from_millis(500) {
        return Err("too frequent commands".into());
    }
    *last = Instant::now();
    Ok(())
}

fn cleanup_vpn(state: &VpnState) {
    let pid = state.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
    let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
    let _ = guard.take();
    if let Some(pid) = pid {
        graceful_kill_pid(pid);
    }
    let mode = state.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if mode == vpn::VpnMode::Proxy {
        let _ = vpn::set_system_proxy(false);
    }
}

/// Результат попытки запуска sing-box
enum StartOutcome {
    /// sing-box стартовал и готов
    Ready,
    /// sing-box сам завершился (wintun race / ошибка) — драйвер "прогрет", kill не нужен
    Crashed(String),
    /// Таймаут — sing-box завис, был убит
    Timeout,
}

/// Одна попытка запуска sing-box
async fn attempt_start_singbox(
    app: &AppHandle,
    state: &State<'_, VpnState>,
    config_str: &str,
    data_dir: &std::path::Path,
    vpn_mode: &vpn::VpnMode,
    timeout_secs: u64,
) -> StartOutcome {
    let mut cmd = match app.shell().sidecar("sing-box") {
        Ok(c) => c.args(["run", "-c", config_str]),
        Err(e) => return StartOutcome::Crashed(e.to_string()),
    };
    if *vpn_mode == vpn::VpnMode::Tun {
        cmd = cmd.current_dir(data_dir);
    }
    let (mut receiver, child) = match cmd.spawn() {
        Ok(r) => r,
        Err(e) => return StartOutcome::Crashed(e.to_string()),
    };

    let child_pid = child.pid();
    *state.process.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
    *state.pid.lock().unwrap_or_else(|e| e.into_inner()) = Some(child_pid);
    *state.mode.lock().unwrap_or_else(|e| e.into_inner()) = vpn_mode.clone();

    let app_clone = app.clone();
    // true = ready ("sing-box started"), false = crashed (Terminated)
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<bool>();
    let ready_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(ready_tx)));
    let expected_pid = child_pid;

    tauri::async_runtime::spawn(async move {
        use tauri_plugin_shell::process::CommandEvent;
        while let Some(event) = receiver.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let line = String::from_utf8_lossy(&bytes).trim().to_string();
                    if !line.is_empty() {
                        if line.contains("sing-box started") {
                            if let Some(tx) = ready_tx.lock().await.take() {
                                let _ = tx.send(true);
                            }
                        }
                        let _ = app_clone.emit("singbox-log", line);
                    }
                }
                CommandEvent::Terminated(status) => {
                    // sing-box сам завершился -> сигнал false (crashed)
                    if let Some(tx) = ready_tx.lock().await.take() {
                        let _ = tx.send(false);
                    }
                    // Очищаем state только если PID совпадает (защита от race при retry)
                    if let Some(st) = app_clone.try_state::<VpnState>() {
                        let current_pid = *st.pid.lock().unwrap_or_else(|e| e.into_inner());
                        if current_pid == Some(expected_pid) {
                            let mode = st.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
                            if mode == vpn::VpnMode::Proxy {
                                let _ = vpn::set_system_proxy(false);
                            }
                            let _ = st.process.lock().unwrap_or_else(|e| e.into_inner()).take();
                            let _ = st.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
                        }
                    }
                    let msg = format!(
                        "sing-box exited (code: {})",
                        status.code.map(|c| c.to_string()).unwrap_or("?".into())
                    );
                    let _ = app_clone.emit("singbox-terminated", msg);
                    break;
                }
                _ => {}
            }
        }
    });

    // Ждем: ready (true), crashed (false), или таймаут
    match tokio::time::timeout(Duration::from_secs(timeout_secs), ready_rx).await {
        Ok(Ok(true)) => {
            // sing-box стартовал успешно
            if *vpn_mode == vpn::VpnMode::Proxy {
                if let Err(e) = vpn::set_system_proxy(true) {
                    return StartOutcome::Crashed(e);
                }
            }
            StartOutcome::Ready
        }
        Ok(Ok(false)) | Ok(Err(_)) => {
            // sing-box сам упал — драйвер "прогрет", kill не нужен
            StartOutcome::Crashed("sing-box terminated with error".into())
        }
        Err(_) => {
            // Таймаут — sing-box завис, нужен kill
            let failed_pid = {
                let pid = state.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
                let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
                let _ = guard.take();
                pid
            };
            if let Some(pid) = failed_pid {
                let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
            }
            StartOutcome::Timeout
        }
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

    // TUN cooldown: wait at least 2s after previous TUN stop
    if vpn_mode == vpn::VpnMode::Tun {
        let last_stop = *state.last_tun_stop.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(stop_time) = last_stop {
            let elapsed = stop_time.elapsed();
            if elapsed < Duration::from_secs(2) {
                tokio::time::sleep(Duration::from_secs(2) - elapsed).await;
            }
        }
    }

    if vpn_mode == vpn::VpnMode::Tun && !is_elevated() {
        return Err("TUN requires administrator privileges".into());
    }

    let params = vpn::parse_vless_uri(&uri)?;
    let config_json =
        serde_json::to_string_pretty(&vpn::generate_singbox_config(
            &params, &bypass_vpn, &bypass_apps, &vpn_mode,
        ))
        .map_err(|e| e.to_string())?;

    let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    let config_path = data_dir.join("singbox.json");
    std::fs::write(&config_path, &config_json).map_err(|e| e.to_string())?;

    // Copy wintun.dll for TUN mode
    if vpn_mode == vpn::VpnMode::Tun {
        let wintun_dst = data_dir.join("wintun.dll");
        if !wintun_dst.exists() {
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
            if let Some(src) = candidates.iter().find(|p| p.exists()) {
                std::fs::copy(src, &wintun_dst).map_err(|e| format!("copy wintun.dll: {e}"))?;
            } else {
                return Err("wintun.dll not found".into());
            }
        }
    }

    // Graceful kill previous process
    let prev_pid = {
        let pid = state.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
        let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
        let _ = guard.take();
        pid
    };
    if let Some(pid) = prev_pid {
        let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
    }

    // Kill orphan sing-box processes
    let _ = tauri::async_runtime::spawn_blocking(kill_orphan_singbox).await;

    // SHA256 verify sing-box binary
    {
        let sidecar_path = app.path().resource_dir().map_err(|e| e.to_string())?
            .join("binaries").join("sing-box-x86_64-pc-windows-msvc.exe");
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

    let config_str = config_path.to_str().ok_or("invalid config path")?.to_string();

    // TUN: up to 5 attempts. Proxy: 1 attempt.
    // Key insight: when sing-box CRASHES (wintun race condition), the driver gets "warmed up".
    // On retry the adapter creates instantly. So we distinguish Crashed vs Timeout:
    //   Crashed -> quick retry (1s, no kill needed — process already dead)
    //   Timeout -> kill + longer retry (2s)
    let max_attempts: u32 = if vpn_mode == vpn::VpnMode::Tun { 3 } else { 1 };
    let mut last_err = String::new();

    // Pre-warm WinTUN: load driver into kernel before first attempt
    if vpn_mode == vpn::VpnMode::Tun {
        let _ = tauri::async_runtime::spawn_blocking(|| {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("sc")
                    .args(["start", "wintun"])
                    .creation_flags(0x08000000)
                    .output();
            }
        }).await;
    }

    for attempt in 1..=max_attempts {
        // TUN timeout MUST be > sing-box's internal wintun timeout (~10s).
        // If we kill sing-box before it crashes naturally, wintun driver
        // doesn't get "warmed up" and every retry fails the same way.
        // 15s lets sing-box fail on its own -> Crashed path -> quick 1s retry.
        let timeout_secs: u64 = if vpn_mode == vpn::VpnMode::Tun {
            15
        } else {
            5
        };

        if attempt > 1 {
            let _ = app.emit("singbox-log",
                format!("[tun-retry] attempt {}/{} (timeout {}s)...", attempt, max_attempts, timeout_secs));
        }

        match attempt_start_singbox(&app, &state, &config_str, &data_dir, &vpn_mode, timeout_secs).await {
            StartOutcome::Ready => return Ok(()),
            StartOutcome::Crashed(e) => {
                // sing-box died on its own — driver is now warm. Quick retry.
                last_err = e;
                if attempt < max_attempts {
                    let _ = app.emit("singbox-log",
                        format!("[tun-retry] sing-box crashed (driver warming up): {}", last_err));
                    // Short pause — process already dead, just let wintun settle
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            StartOutcome::Timeout => {
                // sing-box hung — we killed it. Longer retry with orphan cleanup.
                last_err = format!("sing-box did not start within {}s", timeout_secs);
                if attempt < max_attempts {
                    let _ = app.emit("singbox-log",
                        format!("[tun-retry] timeout after {}s, retrying...", timeout_secs));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let _ = tauri::async_runtime::spawn_blocking(kill_orphan_singbox).await;
                }
            }
        }
    }

    Err(last_err)
}

#[tauri::command]
async fn update_tray_icon(app: AppHandle, connected: bool) -> Result<(), String> {
    let icon_name = if connected { "icons/1act.png" } else { "icons/2dis.png" };
    let icon_path = app.path().resource_dir().map_err(|e| e.to_string())?.join(icon_name);
    let image = Image::from_path(&icon_path).map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_icon(Some(image)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn stop_vpn(state: State<'_, VpnState>) -> Result<(), String> {
    check_rate_limit(&state)?;
    let (pid, had_process, mode) = {
        let pid = state.pid.lock().unwrap_or_else(|e| e.into_inner()).take();
        let mut guard = state.process.lock().unwrap_or_else(|e| e.into_inner());
        let had_process = guard.take().is_some();
        let mode = state.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
        (pid, had_process, mode)
    };
    if let Some(pid) = pid {
        let _ = tauri::async_runtime::spawn_blocking(move || graceful_kill_pid(pid)).await;
    }
    if mode == vpn::VpnMode::Proxy {
        vpn::set_system_proxy(false)?;
    }
    if mode == vpn::VpnMode::Tun && had_process {
        *state.last_tun_stop.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }
    Ok(())
}

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    use windows_sys::Win32::Foundation::LocalFree;
    let mut input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe { CryptProtectData(&mut input, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), 0, &mut output) };
    if ok == 0 { return Err("DPAPI CryptProtectData failed".into()); }
    let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { std::ptr::write_bytes(output.pbData, 0, output.cbData as usize); LocalFree(output.pbData as *mut _); };
    Ok(result)
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    use windows_sys::Win32::Foundation::LocalFree;
    let mut input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe { CryptUnprotectData(&mut input, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), 0, &mut output) };
    if ok == 0 { return Err("DPAPI CryptUnprotectData failed".into()); }
    let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { std::ptr::write_bytes(output.pbData, 0, output.cbData as usize); LocalFree(output.pbData as *mut _); };
    Ok(result)
}

#[tauri::command]
fn encrypt_string(value: String) -> Result<String, String> {
    #[cfg(windows)]
    { let encrypted = dpapi_protect(value.as_bytes())?; use base64::Engine; Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted)) }
    #[cfg(not(windows))]
    Ok(value)
}

#[tauri::command]
fn update_tray_labels(app: AppHandle, show_label: String, quit_label: String) -> Result<(), String> {
    let show_i = MenuItem::with_id(&app, "show", &show_label, true, None::<&str>).map_err(|e| e.to_string())?;
    let quit_i = MenuItem::with_id(&app, "quit", &quit_label, true, None::<&str>).map_err(|e| e.to_string())?;
    let menu = Menu::with_items(&app, &[&show_i, &quit_i]).map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn validate_route(entry: String) -> (String, bool) {
    vpn::validate_route_entry(&entry)
}

#[tauri::command]
fn decrypt_string(value: String) -> Result<String, String> {
    #[cfg(windows)]
    { use base64::Engine; let data = base64::engine::general_purpose::STANDARD.decode(&value).map_err(|e| e.to_string())?; let decrypted = dpapi_unprotect(&data)?; String::from_utf8(decrypted).map_err(|e| e.to_string()) }
    #[cfg(not(windows))]
    Ok(value)
}

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
            let _ = vpn::set_system_proxy(false);
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(windows)]
    cleanup_stale_proxy();

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = vpn::set_system_proxy(false);
        kill_orphan_singbox();
        default_hook(info);
    }));

    tauri::Builder::default()
        .manage(VpnState {
            process: Mutex::new(None),
            pid: Mutex::new(None),
            mode: Mutex::new(vpn::VpnMode::Proxy),
            last_command: Mutex::new(Instant::now() - Duration::from_secs(1)),
            last_tun_stop: Mutex::new(None),
        })
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent, None,
        ))
        .setup(|app| {
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
            let tray_icon_path = app.path().resource_dir().map_err(|e| e.to_string())?.join("icons/2dis.png");
            let tray_icon = Image::from_path(&tray_icon_path).map_err(|e| e.to_string())?;

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
                        button_state: MouseButtonState::Up, ..
                    } = event {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("main") {
                            if win.is_visible().unwrap_or(false) { let _ = win.hide(); }
                            else { let _ = win.show(); let _ = win.set_focus(); }
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
        .invoke_handler(tauri::generate_handler![start_vpn, stop_vpn, update_tray_icon, encrypt_string, decrypt_string, update_tray_labels, validate_route])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
