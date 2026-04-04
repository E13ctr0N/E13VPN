import { useState } from "react";
import { Titlebar } from "./components/Titlebar";
import { VpnScreen } from "./components/VpnScreen";
import { RoutesScreen } from "./components/RoutesScreen";
import { LogsScreen } from "./components/LogsScreen";
import { BottomNav, Tab } from "./components/BottomNav";

function App() {
  const [tab, setTab] = useState<Tab>("vpn");
  const [connected, setConnected] = useState(false);
  const [logLines, setLogLines] = useState<string[]>([]);

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: "var(--color-bg)",
        border: connected ? "1px solid var(--color-border-active)" : "1px solid var(--color-border)",
        borderRadius: "var(--radius-lg)",
        overflow: "hidden",
        transition: "border-color 0.3s",
      }}
    >
      <Titlebar connected={connected} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ flex: 1, display: tab === "vpn" ? "flex" : "none", overflow: "hidden" }}>
          <VpnScreen
            connected={connected}
            setConnected={setConnected}
            logLines={logLines}
            setLogLines={setLogLines}
          />
        </div>
        <div style={{ flex: 1, display: tab === "routes" ? "flex" : "none", flexDirection: "column", overflow: "hidden" }}>
          <RoutesScreen />
        </div>
        <div style={{ flex: 1, display: tab === "logs" ? "flex" : "none", flexDirection: "column", overflow: "hidden" }}>
          <LogsScreen logLines={logLines} />
        </div>
      </div>
      <BottomNav active={tab} onChange={setTab} />
    </div>
  );
}

export default App;
