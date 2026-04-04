interface ModeSelectorProps {
  mode: "proxy" | "tun";
  onChange: (m: "proxy" | "tun") => void;
  disabled: boolean;
}

export function ModeSelector({ mode, onChange, disabled }: ModeSelectorProps) {
  return (
    <div style={{ display: "flex", gap: "2px" }}>
      <ModeBtn label="Proxy" active={mode === "proxy"} disabled={disabled} onClick={() => onChange("proxy")} />
      <ModeBtn label="TUN" active={mode === "tun"} disabled={disabled} onClick={() => onChange("tun")} />
    </div>
  );
}

function ModeBtn({ label, active, disabled, onClick }: { label: string; active: boolean; disabled: boolean; onClick: () => void }) {
  return (
    <button
      onClick={disabled ? undefined : onClick}
      style={{
        padding: "4px 14px",
        fontSize: "9px",
        fontWeight: 500,
        fontFamily: "var(--font-system)",
        borderRadius: "var(--radius-sm)",
        border: "none",
        background: active ? "var(--color-surface-hover)" : "transparent",
        color: active ? "var(--color-text-secondary)" : "var(--color-text-dim)",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "background 0.15s, color 0.15s",
      }}
    >
      {label}
    </button>
  );
}
