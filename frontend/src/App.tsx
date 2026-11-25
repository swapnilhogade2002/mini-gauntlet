import { useEffect, useState } from "react";
import { ScanPage } from "./ScanPage";
import { ScansPage } from "./ScansPage";

function currentScanId(): string | null {
  const match = /^#\/scans\/([\w-]+)$/.exec(window.location.hash);
  return match ? match[1] : null;
}

export default function App() {
  const [scanId, setScanId] = useState(currentScanId);
  useEffect(() => {
    const onChange = () => setScanId(currentScanId());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  return (
    <>
      <header className="top">
        <a href="#/" className="brand">Mini Gauntlet</a>
        <span className="muted">Cloud posture scanner</span>
      </header>
      <main>{scanId ? <ScanPage scanId={scanId} /> : <ScansPage />}</main>
    </>
  );
}
