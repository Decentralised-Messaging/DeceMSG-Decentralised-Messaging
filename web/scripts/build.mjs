import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(".");
const sourceUi = resolve(root, "../decemsg/ui");
const dist = resolve(root, "dist");
const vendor = resolve(root, "node_modules/@matrix-org/matrix-sdk-crypto-wasm");

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await cp(sourceUi, dist, { recursive: true });
await mkdir(resolve(dist, "crypto"), { recursive: true });
await cp(resolve(root, "src/decemsg-crypto.js"), resolve(dist, "crypto/decemsg-crypto.js"));
await cp(vendor, resolve(dist, "vendor/matrix-sdk-crypto-wasm"), { recursive: true });

const indexPath = resolve(dist, "index.html");
const indexHtml = await (await import("node:fs/promises")).readFile(indexPath, "utf8");
const cryptoScript = '<script type="module" src="/ui/crypto/decemsg-crypto.js"></script>';
await writeFile(
  indexPath,
  indexHtml.includes(cryptoScript)
    ? indexHtml
    : indexHtml.replace("</body>", cryptoScript + "</body>"),
);

await writeFile(
  resolve(dist, "BUILD_MANIFEST.json"),
  JSON.stringify({
    product: "DeceMSG",
    build: "browser-crypto-foundation",
    crypto_package: "@matrix-org/matrix-sdk-crypto-wasm",
    crypto_version: "18.4.0",
    crypto_license: "Apache-2.0"
  }, null, 2) + "\n"
);

console.log("Built browser crypto staging tree at " + dist);
