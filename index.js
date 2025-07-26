import createCryptoModule from './dist/crypto-wasm.js';
// import wasmUrl from './dist/crypto.wasm';

let wasmModulePromise = null;

function getModule() {
  if (!wasmModulePromise) {
    wasmModulePromise = createCryptoModule(/*{
      locateFile: () => wasmUrl,
    }*/);
  }
  return wasmModulePromise;
}

/**
 * Computes the SHA-256 hash of a string.
 * @param {string} input The string to hash.
 * @returns {Promise<string>} The SHA-256 hash as a hex string.
 */
export async function sha256(input) {
  const module = await getModule();
  return module.sha256(input);
}

/**
 * Generates a 2048-bit RSA key pair.
 * @returns {Promise<{privateKey: string, publicKey: string}>} An object with PEM-encoded keys.
 */
export async function generateRsaKeyPair() {
  const module = await getModule();
  const keyPair = module.generateRsaKeyPair();
  if (!keyPair) {
    throw new Error("Failed to generate RSA key pair in WASM module.");
  }
  console.log("Generated RSA key pair:", keyPair);
  const result = {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey
  };
  return result;
}