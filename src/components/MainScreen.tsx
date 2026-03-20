import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { load as loadStore, Store } from "@tauri-apps/plugin-store";

const STORE_FILE = "vpn.json";
const MAX_LOG_LINES = 200;

export interface VlessConfig {
  id: string;
  name: string;
  uri: string;
}

function parseConfigName(uri: string): string {
  try {
    const fragment = new URL(uri).hash.slice(1);
    if (fragment) return decodeURIComponent(fragment);
  } catch {}
  try {
    return new URL(uri).hostname;
  } catch {}
  return "без имени";
}

function parseConfigHost(uri: string): string {
  try {
    const s = uri.replace("vless://", "");
    const afterAt = s.split("@")[1] ?? "";
    const hostPort = afterAt.split("?")[0] ?? "";
    const host = hostPort.replace(/:\d+$/, "");
    return host;
  } catch {}
  return "";
}

export function MainScreen() {
  const [configs, setConfigs] = useState<VlessConfig[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [storeReady, setStoreReady] = useState(false);
  const [vpnMode, setVpnMode] = useState<"proxy" | "tun">("proxy");
  const [speed, setSpeed] = useState<{ down: number; up: number } | null>(null);
  const [logLines, setLogLines] = useState<string[]>([]);
  const storeRef = useRef<Store | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  // Загрузка при старте
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

  // Трафик (clash API streaming)
  useEffect(() => {
    if (!connected) {
      setSpeed(null);
      return;
    }
    let cancelled = false;
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    const controller = new AbortController();

    async function streamTraffic() {
      while (!cancelled) {
        try {
          const resp = await fetch("http://127.0.0.1:9090/traffic", {
            signal: controller.signal,
          });
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
        } catch {
          // API not ready, aborted, or connection lost — retry after delay
        }
        if (!cancelled) await new Promise((r) => setTimeout(r, 2000));
      }
    }

    streamTraffic();
    return () => {
      cancelled = true;
      controller.abort();
      reader?.cancel().catch(() => {});
    };
  }, [connected]);

  // Подписка на вывод sing-box
  useEffect(() => {
    const unlistenLog = listen<string>("singbox-log", (e) => {
      setLogLines((prev) => {
        const next = [...prev, e.payload];
        return next.length > MAX_LOG_LINES ? next.slice(-MAX_LOG_LINES) : next;
      });
    });
    const unlistenTerm = listen<string>("singbox-terminated", (e) => {
      setConnected(false);
      invoke("update_tray_icon", { connected: false }).catch(() => {});
      setLogLines((prev) => [...prev, `[terminated] ${e.payload}`]);
    });
    return () => {
      unlistenLog.then((f) => f());
      unlistenTerm.then((f) => f());
    };
  }, []);

  // Автопрокрутка логов (только если пользователь уже внизу)
  useEffect(() => {
    const el = logRef.current;
    if (el) {
      const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
      if (isAtBottom) el.scrollTop = el.scrollHeight;
    }
  }, [logLines]);

  // Сохранение при изменениях
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

  async function addFromClipboard() {
    try {
      const text = (await readText()).trim();
      if (!text.startsWith("vless://")) return;
      const id = crypto.randomUUID();
      const name = parseConfigName(text);
      setConfigs((prev) => [...prev, { id, name, uri: text }]);
      if (!activeId) setActiveId(id);
    } catch {
      // clipboard read error
    }
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
        invoke("update_tray_icon", { connected: true }).catch(() => {});
      } else {
        await invoke("stop_vpn");
        setConnected(false);
        invoke("update_tray_icon", { connected: false }).catch(() => {});
      }
    } catch (e) {
      setLogLines((prev) => [...prev, `[error] ${String(e)}`]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Status bar */}
      <StatusBar connected={connected} busy={busy} mode={vpnMode} speed={speed} />

      {/* Mode selector */}
      <ModeSelector
        mode={vpnMode}
        onChange={setVpnMode}
        disabled={connected || busy}
      />

      {/* Config list */}
      <div style={{ flex: 1, overflowY: "auto", padding: "4px 0" }}>
        {configs.length === 0 ? (
          <EmptyState />
        ) : (
          configs.map((cfg) => (
            <ConfigItem
              key={cfg.id}
              config={cfg}
              active={cfg.id === activeId}
              locked={connected}
              onSelect={() => {
                if (!connected) setActiveId(cfg.id);
              }}
              onRemove={() => removeConfig(cfg.id)}
            />
          ))
        )}
      </div>

      {/* Log area */}
      {logLines.length > 0 && (
        <div
          ref={logRef}
          style={{
            maxHeight: "100px",
            overflowY: "auto",
            borderTop: "1px solid var(--color-border)",
            background: "var(--color-surface)",
            padding: "4px 10px",
            flexShrink: 0,
          }}
        >
          {logLines.map((line, i) => (
            <div
              key={i}
              style={{
                fontSize: "8px",
                lineHeight: "1.4",
                color: /ERROR|FATAL/i.test(line) || line.startsWith("[terminated]")
                  ? "var(--color-danger)"
                  : /WARN/i.test(line)
                  ? "var(--color-accent)"
                  : "var(--color-text-muted)",
                fontFamily: "var(--font-mono)",
                opacity: 0.7,
                wordBreak: "break-all",
              }}
            >
              {line}
            </div>
          ))}
        </div>
      )}

      {/* Bottom bar */}
      <BottomBar
        canConnect={!!activeId}
        connected={connected}
        busy={busy}
        onConnect={toggleConnect}
        onAdd={addFromClipboard}
      />
    </div>
  );
}

function formatSpeed(bytes: number): string {
  if (bytes < 1024) return `${bytes} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB/s`;
}

function StatusBar({
  connected,
  busy,
  mode,
  speed,
}: {
  connected: boolean;
  busy: boolean;
  mode: "proxy" | "tun";
  speed: { down: number; up: number } | null;
}) {
  const color = busy
    ? "var(--color-accent)"
    : connected
    ? "var(--color-success)"
    : "var(--color-border)";
  const modeLabel = connected ? (mode === "tun" ? " / TUN" : " / Proxy") : "";
  const label = busy ? "…" : connected ? `подключено${modeLabel}` : "отключено";

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "7px",
        padding: "6px 14px",
        borderBottom: "1px solid var(--color-border)",
        background: "var(--color-surface)",
        flexShrink: 0,
      }}
    >
      <div
        style={{
          width: "5px",
          height: "5px",
          borderRadius: "50%",
          background: color,
          transition: "background 0.3s",
          flexShrink: 0,
        }}
      />
      <span
        style={{
          flex: 1,
          fontSize: "10px",
          letterSpacing: "0.1em",
          color: "var(--color-text-muted)",
        }}
      >
        {label}
      </span>
      {connected && speed && (
        <span
          style={{
            fontSize: "9px",
            letterSpacing: "0.04em",
            color: "var(--color-text-muted)",
            opacity: 0.7,
          }}
        >
          {"↓ " + formatSpeed(speed.down) + "  ↑ " + formatSpeed(speed.up)}
        </span>
      )}
    </div>
  );
}

function EmptyState() {
  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: "6px",
        color: "var(--color-text-muted)",
      }}
    >
      <span style={{ fontSize: "11px", letterSpacing: "0.1em" }}>— нет конфигов —</span>
      <span style={{ fontSize: "10px", opacity: 0.5 }}>вставьте vless:// из буфера обмена</span>
    </div>
  );
}

function ConfigItem({
  config,
  active,
  locked,
  onSelect,
  onRemove,
}: {
  config: VlessConfig;
  active: boolean;
  locked: boolean;
  onSelect: () => void;
  onRemove: () => void;
}) {
  const host = parseConfigHost(config.uri);

  return (
    <div
      onClick={onSelect}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        padding: "7px 14px 7px 12px",
        cursor: locked ? "default" : "pointer",
        background: active ? "var(--color-surface-2)" : "transparent",
        borderLeft: `2px solid ${active ? "var(--color-accent)" : "transparent"}`,
        transition: "background 0.1s",
      }}
    >
      <div
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          flexShrink: 0,
          background: active ? "var(--color-accent)" : "var(--color-border)",
          transition: "background 0.15s",
        }}
      />
      <div style={{ flex: 1, overflow: "hidden" }}>
        <div
          style={{
            fontSize: "12px",
            color: active ? "var(--color-text)" : "var(--color-text-muted)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {config.name}
        </div>
        {host && (
          <div
            style={{
              fontSize: "9px",
              color: "var(--color-text-muted)",
              opacity: 0.5,
              marginTop: "1px",
            }}
          >
            {host}
          </div>
        )}
      </div>
      <button
        onClick={(e) => {
          e.stopPropagation();
          onRemove();
        }}
        title="Удалить"
        style={{
          width: "20px",
          height: "20px",
          border: "none",
          background: "transparent",
          color: "var(--color-text-muted)",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          borderRadius: "var(--radius-sm)",
          flexShrink: 0,
          padding: 0,
          transition: "color 0.1s, background 0.1s",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.color = "var(--color-danger)";
          e.currentTarget.style.background = "rgba(159,106,106,0.15)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.color = "var(--color-text-muted)";
          e.currentTarget.style.background = "transparent";
        }}
      >
        <svg width="8" height="8" viewBox="0 0 8 8" fill="none">
          <line x1="1" y1="1" x2="7" y2="7" stroke="currentColor" strokeWidth="1.5" />
          <line x1="7" y1="1" x2="1" y2="7" stroke="currentColor" strokeWidth="1.5" />
        </svg>
      </button>
    </div>
  );
}

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
        key={value}
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

function BottomBar({
  canConnect,
  connected,
  busy,
  onConnect,
  onAdd,
}: {
  canConnect: boolean;
  connected: boolean;
  busy: boolean;
  onConnect: () => void;
  onAdd: () => void;
}) {
  const btnLabel = busy ? "…" : connected ? "Отключить" : "Подключить";
  const btnBg = canConnect ? "var(--color-accent)" : "var(--color-surface-2)";

  return (
    <div
      style={{
        padding: "12px 14px",
        borderTop: "1px solid var(--color-border)",
        display: "flex",
        gap: "8px",
        background: "var(--color-surface)",
        flexShrink: 0,
      }}
    >
      <button
        onClick={onAdd}
        disabled={busy}
        title="Добавить из буфера"
        style={{
          flex: 1,
          height: "36px",
          border: "1px solid var(--color-border)",
          borderRadius: "var(--radius-md)",
          background: "transparent",
          color: "var(--color-text-muted)",
          cursor: busy ? "not-allowed" : "pointer",
          fontSize: "11px",
          letterSpacing: "0.08em",
          fontFamily: "var(--font-mono)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: "6px",
          transition: "border-color 0.15s, color 0.15s",
          opacity: busy ? 0.45 : 1,
        }}
        onMouseEnter={(e) => {
          if (!busy) {
            e.currentTarget.style.borderColor = "var(--color-accent)";
            e.currentTarget.style.color = "var(--color-accent)";
          }
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.borderColor = "var(--color-border)";
          e.currentTarget.style.color = "var(--color-text-muted)";
        }}
      >
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
          <line x1="5" y1="1" x2="5" y2="9" stroke="currentColor" strokeWidth="1.5" />
          <line x1="1" y1="5" x2="9" y2="5" stroke="currentColor" strokeWidth="1.5" />
        </svg>
        Добавить
      </button>

      <button
        onClick={onConnect}
        disabled={!canConnect || busy}
        style={{
          flex: 2,
          height: "36px",
          border: "none",
          borderRadius: "var(--radius-md)",
          background: btnBg,
          color: canConnect ? "#0d0d0d" : "var(--color-text-muted)",
          cursor: canConnect && !busy ? "pointer" : "not-allowed",
          fontSize: "11px",
          letterSpacing: "0.12em",
          fontFamily: "var(--font-mono)",
          fontWeight: 600,
          textTransform: "uppercase",
          opacity: connected ? 0.5 : canConnect && !busy ? 1 : 0.45,
          transition: "background 0.2s, color 0.2s, opacity 0.2s",
        }}
      >
        {btnLabel}
      </button>
    </div>
  );
}
