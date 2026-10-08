import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

// Kept narrow on purpose: catch the bugs that break the UI at runtime.
export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: { parser: tseslint.parser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "off",
    },
  },
);
