import { getCurrentWindow } from "@tauri-apps/api/window";

const win = getCurrentWindow();

export function Titlebar() {
  return (
    <div
      data-tauri-drag-region
      style={{
        height: "32px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 12px 0 16px",
        background: "var(--color-surface)",
        borderBottom: "1px solid var(--color-border)",
        flexShrink: 0,
      }}
    >
      <span
        data-tauri-drag-region
        style={{
          fontSize: "11px",
          letterSpacing: "0.12em",
          color: "var(--color-text-muted)",
          textTransform: "uppercase",
        }}
      >
        E13VPN
      </span>

      <div style={{ display: "flex", gap: "4px" }}>
        <TitlebarBtn
          title="Свернуть"
          onClick={() => win.minimize()}
          icon={
            <svg width="10" height="2" viewBox="0 0 10 2" fill="none">
              <line x1="0" y1="1" x2="10" y2="1" stroke="currentColor" strokeWidth="1.5" />
            </svg>
          }
        />
        <TitlebarBtn
          title="Закрыть"
          onClick={() => win.close()}
          danger
          icon={
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
              <line x1="1" y1="1" x2="9" y2="9" stroke="currentColor" strokeWidth="1.5" />
              <line x1="9" y1="1" x2="1" y2="9" stroke="currentColor" strokeWidth="1.5" />
            </svg>
          }
        />
      </div>
    </div>
  );
}

function TitlebarBtn({
  onClick,
  icon,
  title,
  danger,
}: {
  onClick: () => void;
  icon: React.ReactNode;
  title: string;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      style={{
        width: "24px",
        height: "24px",
        border: "none",
        borderRadius: "var(--radius-sm)",
        background: "transparent",
        color: "var(--color-text-muted)",
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        transition: "background 0.15s, color 0.15s",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = danger
          ? "var(--color-danger)"
          : "var(--color-surface-2)";
        e.currentTarget.style.color = danger ? "#fff" : "var(--color-text)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "transparent";
        e.currentTarget.style.color = "var(--color-text-muted)";
      }}
    >
      {icon}
    </button>
  );
}
