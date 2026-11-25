import { useEffect, useRef } from "react";

/** Calls `callback` every `ms` while `active` is true. */
export function usePolling(callback: () => void, active: boolean, ms = 1500) {
  const saved = useRef(callback);
  useEffect(() => {
    saved.current = callback;
  });
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => saved.current(), ms);
    return () => clearInterval(timer);
  }, [active, ms]);
}
