import typescript from "@rollup/plugin-typescript";
import { defineConfig } from "rollup";
import dts from "rollup-plugin-dts";

export default defineConfig([
  {
    input: "src/index.ts",
    output: [
      { file: "dist/index.mjs", sourcemap: true },
      { file: "dist/index.js", sourcemap: true, format: "commonjs", exports: "auto" },
    ],
    plugins: [typescript()],
  },
  {
    input: "src/index.ts",
    output: { file: "dist/index.d.ts" },
    plugins: [dts()],
  },
]);
