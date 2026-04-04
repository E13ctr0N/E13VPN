import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { load as loadStore, Store } from "@tauri-apps/plugin-store";
import { PowerButton } from "./PowerButton";
import { SpeedDisplay } from "./SpeedDisplay";
import { ModeSelector } from "./ModeSelector";
import { ConfigList, VlessConfig } from "./ConfigList";

const STORE_FILE = "vpn.json";

function parseConfigName(uri: string): string {
  try {
    const fragment = new URL(uri).hash.slice(1);
    if (fragment) return decodeURIComponent(fragment);
  } catch {}
  try {
    return new URL(uri).hostname;
  } catch {}
  return "unnamed";
}

interface VpnScreenProps {
  connected: boolean;
  setConnected: (v: boolean) => void;
  setLogLines: React.Dispatch<React.SetStateAction<string[]>>;
}

export function VpnScreen({ connected, setConnected, setLogLines }: VpnScreenProps) {
  const [configs, setConfigs] = useState<VlessConfig[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [storeReady, setStoreReady] = useState(false);
  const [vpnMode, setVpnMode] = useState<"proxy" | "tun">("proxy");
  const [speed, setSpeed] = useState<{ down: number; up: number } | null>(null);
  const [connectTime, setConnectTime] = useState<number | null>(null);
  const [elapsed, setElapsed] = useState("—");
  const storeRef = useRef<Store | null>(null);

  // Load store
  useEffect(() => {
    loadStore(STORE_FILE, { autoSave: false, defaults: {} }).then(async (store) => {
      storeRef.current = store;
      const savedConfigs = (await store.get<VlessConfig[]>("configs")) ?? [];
      const savedActiveId = (await store.get<string>("activeId")) ?? null;
      const savedMode = (await store.get<"proxy" | "tun">("vpn_mode")) ?? "proxy";
      setConfigs(savedConfigs);
      setActiveId(savedActiveId);
      setVpnMode(savedMode);
      setStoreReady(true);
    });
  }, []);

  // Traffic streaming
  useEffect(() => {
    if (!connected) { setSpeed(null); return; }
    let cancelled = false;
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    const controller = new AbortController();

    async function streamTraffic() {
      while (!cancelled) {
        try {
          const resp = await fetch("http://127.0.0.1:9090/traffic", { signal: controller.signal });
          const body = resp.body;
          if (!body) continue;
          reader = body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          while (!cancelled) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() ?? "";
            for (const line of lines) {
              if (!line.trim()) continue;
              try {
                const data = JSON.parse(line);
                setSpeed({ down: data.down ?? 0, up: data.up ?? 0 });
              } catch {}
            }
          }
        } catch {}
        if (!cancelled) await new Promise((r) => setTimeout(r, 2000));
      }
    }
    streamTraffic();
    return () => { cancelled = true; controller.abort(); reader?.cancel().catch(() => {}); };
  }, [connected]);

  // Sing-box events
  useEffect(() => {
    const unlistenLog = listen<string>("singbox-log", (e) => {
      setLogLines((prev) => {
        const next = [...prev, e.payload];
        return next.length > 200 ? next.slice(-200) : next;
      });
    });
    const unlistenTerm = listen<string>("singbox-terminated", (e) => {
      setConnected(false);
      setConnectTime(null);
      invoke("update_tray_icon", { connected: false }).catch(() => {});
      setLogLines((prev) => [...prev, `[terminated] ${e.payload}`]);
    });
    return () => { unlistenLog.then((f) => f()); unlistenTerm.then((f) => f()); };
  }, [setConnected, setLogLines]);

  // Save on change
  useEffect(() => {
    if (!storeReady || !storeRef.current) return;
    const store = storeRef.current;
    (async () => {
      await store.set("configs", configs);
      await store.set("activeId", activeId);
      await store.set("vpn_mode", vpnMode);
      await store.save();
    })();
  }, [configs, activeId, vpnMode, storeReady]);

  // Timer
  useEffect(() => {
    if (!connectTime) { setElapsed("—"); return; }
    const interval = setInterval(() => {
      const sec = Math.floor((Date.now() - connectTime) / 1000);
      const m = String(Math.floor(sec / 60)).padStart(2, "0");
      const s = String(sec % 60).padStart(2, "0");
      setElapsed(`${m}:${s}`);
    }, 1000);
    return () => clearInterval(interval);
  }, [connectTime]);

  async function addFromClipboard() {
    try {
      const text = (await readText()).trim();
      if (!text.startsWith("vless://")) return;
      const id = crypto.randomUUID();
      const name = parseConfigName(text);
      setConfigs((prev) => [...prev, { id, name, uri: text }]);
      if (!activeId) setActiveId(id);
    } catch {}
  }

  function removeConfig(id: string) {
    if (connected && id === activeId) return;
    setConfigs((prev) => prev.filter((c) => c.id !== id));
    if (activeId === id) setActiveId(null);
  }

  async function toggleConnect() {
    if (!activeId || busy) return;
    const cfg = configs.find((c) => c.id === activeId)!;
    setBusy(true);
    try {
      if (!connected) {
        setLogLines([]);
        const store = storeRef.current ?? await loadStore(STORE_FILE, { autoSave: false, defaults: {} });
        const bypassVpn = (await store.get<string[]>("routes_bypass")) ?? [];
        const bypassApps = (await store.get<string[]>("routes_bypass_apps")) ?? [];
        await invoke("start_vpn", { uri: cfg.uri, bypassVpn, bypassApps, mode: vpnMode });
        setConnected(true);
        setConnectTime(Date.now());
        invoke("update_tray_icon", { connected: true }).catch(() => {});
      } else {
        await invoke("stop_vpn");
        setConnected(false);
        setConnectTime(null);
        invoke("update_tray_icon", { connected: false }).catch(() => {});
      }
    } catch (e) {
      setLogLines((prev) => [...prev, `[error] ${String(e)}`]);
    } finally {
      setBusy(false);
    }
  }

  const powerState = busy ? "connecting" : connected ? "on" : "off";
  const statusText = busy ? "Connecting..." : connected ? "Connected" : "Disconnected";
  const statusColor = busy
    ? "var(--color-text-tertiary)"
    : connected
    ? "var(--color-text-secondary)"
    : "var(--color-text-muted)";

  return (
    <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
      {/* Left panel */}
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "12px",
          padding: "16px",
        }}
      >
        <PowerButton state={powerState} onClick={toggleConnect} disabled={!activeId || busy} />
        <span style={{ fontSize: "11px", fontWeight: 500, color: statusColor, transition: "color 0.3s" }}>
          {statusText}
        </span>
        <span
          style={{
            fontSize: "9px",
            color: connected ? "var(--color-text-muted)" : "var(--color-text-ghost)",
            transition: "color 0.3s",
          }}
        >
          {elapsed}
        </span>
        <SpeedDisplay speed={speed} active={connected} />
        <ModeSelector mode={vpnMode} onChange={setVpnMode} disabled={connected || busy} />
      </div>

      {/* Divider */}
      <div style={{ width: "1px", background: "var(--color-border)", flexShrink: 0 }} />

      {/* Right panel */}
      <div style={{ flex: 1.1, display: "flex", flexDirection: "column", padding: "14px", overflow: "hidden" }}>
        <ConfigList
          configs={configs}
          activeId={activeId}
          connected={connected}
          onSelect={setActiveId}
          onRemove={removeConfig}
          onPaste={addFromClipboard}
        />
      </div>
    </div>
  );
}
