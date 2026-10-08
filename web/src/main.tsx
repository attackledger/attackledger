import React from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/atkinson-hyperlegible/400.css";
import "@fontsource/atkinson-hyperlegible/700.css";
import "@fontsource/zilla-slab/500.css";
import "@fontsource/zilla-slab/700.css";
import "./styles.css";
import { App } from "./App";
import { applyStoredTheme } from "./theme";

applyStoredTheme();

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
