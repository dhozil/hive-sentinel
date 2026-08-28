// Bundle Vercel functions menjadi SATU file (pola project verify: cold-start cepat).
import { build } from "esbuild";

const targets = ["dashboard", "simulate-attack"];

for (const name of targets) {
  await build({
    entryPoints: [`api/${name}.mjs`],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    outfile: `api/${name}.mjs`,
    allowOverwrite: true,
    logLevel: "info",
  });
  console.log(`bundled api/${name}.mjs`);
}
// ping tidak bergantung dependency apa pun — biarkan apa adanya.