export type Tab = "vpn" | "routes" | "logs";

interface BottomNavProps {
  active: Tab;
  onChange: (tab: Tab) => void;
}

export function BottomNav({ active, onChange }: BottomNavProps) {
  return (
    <div
      style={{
        height: "32px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "24px",
        borderTop: "1px solid #161616",
        background: "var(--color-titlebar)",
        flexShrink: 0,
      }}
    >
      <NavItem label="VPN" active={active === "vpn"} onClick={() => onChange("vpn")} />
      <NavItem label="Routes" active={active === "routes"} onClick={() => onChange("routes")} />
      <NavItem label="Logs" active={active === "logs"} onClick={() => onChange("logs")} />
    </div>
  );
}

function NavItem({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <span
      onClick={onClick}
      style={{
        fontSize: "9px",
        cursor: "pointer",
        color: active ? "var(--color-text-secondary)" : "var(--color-text-dim)",
        borderBottom: active ? "1px solid var(--color-text-tertiary)" : "1px solid transparent",
        paddingBottom: "1px",
        transition: "color 0.15s, border-color 0.15s",
      }}
    >
      {label}
    </span>
  );
}
