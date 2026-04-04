import { getCurrentWindow } from "@tauri-apps/api/window";

const win = getCurrentWindow();

export function Titlebar({ connected }: { connected?: boolean }) {
  return (
    <div
      data-tauri-drag-region
      style={{
        height: "36px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 14px",
        background: "var(--color-titlebar)",
        borderBottom: "1px solid var(--color-border)",
        flexShrink: 0,
      }}
    >
      <span
        data-tauri-drag-region
        style={{
          fontSize: "12px",
          fontWeight: 500,
          color: connected ? "#777" : "#555",
          transition: "color 0.3s",
        }}
      >
        E13VPN
      </span>

      <div style={{ display: "flex", gap: "7px" }}>
        <WinBtn onClick={() => win.minimize()} />
        <WinBtn onClick={() => win.close()} danger />
      </div>
    </div>
  );
}

function WinBtn({ onClick, danger }: { onClick: () => void; danger?: boolean }) {
  return (
    <div
      onClick={onClick}
      style={{
        width: "10px",
        height: "10px",
        borderRadius: "50%",
        background: danger ? "var(--color-danger)" : "var(--color-text-ghost)",
        cursor: "pointer",
        transition: "opacity 0.15s",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.7")}
      onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
    />
  );
}
