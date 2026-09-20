import { defineConfig } from "vite";
import path from "path";
import { fileURLToPath } from "url";

const root = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(root, "..", "out");

export default defineConfig({
  server: {
    fs: {
      allow: [root, outDir],
    },
  },
  // Serve extracted assets at site root (manifest.json, textures/, …)
  publicDir: outDir,
});
