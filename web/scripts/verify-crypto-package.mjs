import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const packagePath = resolve("node_modules/@matrix-org/matrix-sdk-crypto-wasm/package.json");
const wasmPath = resolve("node_modules/@matrix-org/matrix-sdk-crypto-wasm/pkg/matrix_sdk_crypto_wasm_bg.wasm");
const pkg = JSON.parse(await readFile(packagePath, "utf8"));

if (pkg.version !== "18.4.0") {
  throw new Error("Unexpected crypto package version: " + pkg.version);
}
if (pkg.license !== "Apache-2.0") {
  throw new Error("Unexpected crypto package license: " + pkg.license);
}
await readFile(wasmPath);
console.log("Verified @matrix-org/matrix-sdk-crypto-wasm 18.4.0 (Apache-2.0) with browser WASM payload.");
