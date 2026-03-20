import { useState } from "react";
import { Titlebar } from "./components/Titlebar";
import { MainScreen } from "./components/MainScreen";
import { RoutesScreen } from "./components/RoutesScreen";

type Tab = "configs" | "routes";

function App() {
  const [tab, setTab] = useState<Tab>("configs");

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: "var(--color-bg)",
        border: "1px solid var(--color-border)",
        borderRadius: "var(--radius-lg)",
        overflow: "hidden",
      }}
    >
      <Titlebar />
      <TabBar active={tab} onChange={setTab} />
      <div style={{ flex: 1, display: tab === "configs" ? "flex" : "none", flexDirection: "column", overflow: "hidden" }}>
        <MainScreen />
      </div>
      <div style={{ flex: 1, display: tab === "routes" ? "flex" : "none", flexDirection: "column", overflow: "hidden" }}>
        <RoutesScreen />
      </div>
    </div>
  );
}

function TabBar({ active, onChange }: { active: Tab; onChange: (t: Tab) => void }) {
  return (
    <div
      style={{
        display: "flex",
        borderBottom: "1px solid var(--color-border)",
        background: "var(--color-surface)",
        flexShrink: 0,
      }}
    >
      <TabBtn active={active === "configs"} onClick={() => onChange("configs")}>
        Конфиги
      </TabBtn>
      <TabBtn active={active === "routes"} onClick={() => onChange("routes")}>
        Маршруты
      </TabBtn>
    </div>
  );
}

function TabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        flex: 1,
        height: "28px",
        border: "none",
        borderBottom: `2px solid ${active ? "var(--color-accent)" : "transparent"}`,
        background: "transparent",
        color: active ? "var(--color-accent)" : "var(--color-text-muted)",
        cursor: "pointer",
        fontSize: "10px",
        letterSpacing: "0.1em",
        textTransform: "uppercase",
        fontFamily: "var(--font-mono)",
        transition: "color 0.15s, border-color 0.15s",
      }}
    >
      {children}
    </button>
  );
}

export default App;
