# VPN Client Bugfix & Hardening Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all critical bugs, security issues, and apply best-practice hardening found during code review.

**Architecture:** Backend fixes in Rust (lib.rs, vpn.rs), frontend fixes in React (MainScreen.tsx, RoutesScreen.tsx), config fixes (tauri.conf.json, capabilities/default.json).

**Tech Stack:** Rust, Tauri v2, React, TypeScript, sing-box

---

### Task 1: Fix proxy leak on sing-box crash (CRITICAL #1)

**Files:**
- Modify: `src-tauri/src/lib.rs:93-104`

When sing-box terminates unexpectedly, auto-reset system proxy and clear process state.

**Changes:**
In the `CommandEvent::Terminated` handler, add proxy cleanup:
```rust
CommandEvent::Terminated(status) => {
    // Auto-cleanup: reset proxy if was in proxy mode
    if let Some(st) = app_clone.try_state::<VpnState>() {
        let mode = st.mode.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if mode == vpn::VpnMode::Proxy {
            let _ = vpn::set_system_proxy(false);
        }
        let _ = st.process.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
    // emit event...
    break;
}
```

---

### Task 2: Fix mutex poisoning panic (CRITICAL #2)

**Files:**
- Modify: `src-tauri/src/lib.rs` (all `.lock().unwrap()` calls)

Replace all `.lock().unwrap()` with `.lock().unwrap_or_else(|e| e.into_inner())`.

---

### Task 3: Set CSP (CRITICAL #3)

**Files:**
- Modify: `src-tauri/tauri.conf.json:24-25`

Set minimal CSP instead of null.

---

### Task 4: Fix percent_decode for UTF-8 (IMPORTANT #9)

**Files:**
- Modify: `src-tauri/src/vpn.rs:29-47`

Collect bytes into Vec<u8>, then convert with String::from_utf8_lossy.

---

### Task 5: Fix is_network_entry heuristic (IMPORTANT #6)

**Files:**
- Modify: `src-tauri/src/vpn.rs:102-104`

Use proper IP address parsing instead of weak char check.

---

### Task 6: Add route_exclude_address + auto_detect_interface for TUN (CRITICAL #19, #20)

**Files:**
- Modify: `src-tauri/src/vpn.rs` (generate_singbox_config)

Add server IP exclusion to prevent routing loop, add auto_detect_interface, add mtu.

---

### Task 7: Fix DNS config (IMPORTANT #7, #14, #21, #22)

**Files:**
- Modify: `src-tauri/src/vpn.rs` (build_dns)

- Replace 223.5.5.5 with tls://1.1.1.1
- Add strategy: ipv4_only to DNS servers
- Add DNS section for proxy mode too

---

### Task 8: Add race condition fix — wait for port before setting proxy (IMPORTANT #5)

**Files:**
- Modify: `src-tauri/src/lib.rs:106-108`

Add TCP port check loop before setting system proxy.

---

### Task 9: Cleanup orphan sing-box processes on start (IMPORTANT #23)

**Files:**
- Modify: `src-tauri/src/lib.rs` (start_vpn)

Kill any existing sing-box.exe before starting new one.

---

### Task 10: Fix store double-loading (IMPORTANT #10)

**Files:**
- Modify: `src/components/MainScreen.tsx`
- Modify: `src/components/RoutesScreen.tsx`

Cache store instance in useRef.

---

### Task 11: Security hardening — capabilities & CSP (IMPORTANT #11, #16)

**Files:**
- Modify: `src-tauri/capabilities/default.json`

Remove clipboard-manager:allow-write-text, restrict shell args.

---

### Task 12: Add on_exit cleanup hook (SUGGESTION #17)

**Files:**
- Modify: `src-tauri/src/lib.rs` (setup)

Add cleanup on app exit to guarantee proxy reset.
