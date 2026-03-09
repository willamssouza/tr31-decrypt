const crypto = require("crypto");

function validatePin(pin) {
  if (typeof pin !== "string" || !/^\d{4,12}$/.test(pin)) {
    throw new Error(
      "PIN deve conter apenas digitos e ter de 4 a 12 caracteres",
    );
  }
}

function validatePan(pan) {
  if (typeof pan !== "string" || !/^\d{12,19}$/.test(pan)) {
    throw new Error(
      "PAN deve conter apenas digitos e ter de 12 a 19 caracteres",
    );
  }
}

function resolveAesAlgorithmFromKeyLength(keyLength) {
  if (keyLength === 16) return "aes-128-ecb";
  if (keyLength === 24) return "aes-192-ecb";
  if (keyLength === 32) return "aes-256-ecb";
  throw new Error(
    "PKEY deve ter 16, 24 ou 32 bytes (hex com 32, 48 ou 64 chars)",
  );
}

function xorHexNibbles(hexA, hexB) {
  if (hexA.length !== hexB.length) {
    throw new Error("Blocos devem ter o mesmo tamanho para operacao XOR");
  }

  let result = "";
  for (let i = 0; i < hexA.length; i += 1) {
    const a = parseInt(hexA[i], 16);
    const b = parseInt(hexB[i], 16);
    result += (a ^ b).toString(16);
  }

  return result.toUpperCase();
}

/**
 * Monta o PIN block claro ISO-4 (16 bytes / 32 nibbles) antes da criptografia.
 * Estrutura usada:
 * - Campo PIN: 4 | pinLength | pinDigits | pad 'A' ate 16 nibbles, seguido de 16 nibbles aleatorios
 * - Campo PAN: 20 nibbles '0' + 12 digitos mais a direita do PAN sem digito verificador
 */
function buildIso4ClearPinBlock(pin, pan, randomHex) {
  validatePin(pin);
  validatePan(pan);

  const normalizedRandomHex =
    typeof randomHex === "string"
      ? randomHex.toUpperCase()
      : crypto.randomBytes(8).toString("hex").toUpperCase();

  if (!/^[0-9A-F]{16}$/.test(normalizedRandomHex)) {
    throw new Error(
      "randomHex deve ser hexadecimal com 16 caracteres (8 bytes)",
    );
  }

  const pinLengthNibble = pin.length.toString(16).toUpperCase();
  const pinPrefix = `4${pinLengthNibble}${pin}`;
  const pinFieldLeft = pinPrefix.padEnd(16, "A");
  const pinField = `${pinFieldLeft}${normalizedRandomHex}`;

  const panWithoutCheckDigit = pan.slice(0, -1);
  const pan12RightMost = panWithoutCheckDigit.slice(-12);
  const panField = `00000000000000000000${pan12RightMost}`;

  console.log("PIN Field (Hex):", pinField);
  console.log("PAN Field (Hex):", panField);
  return xorHexNibbles(pinField, panField);
}

/**
 * Criptografa um PIN block ISO-4 usando PKEY AES (ECB sem padding).
 */
function encryptIso4PinBlock(pin, pan, pkeyHex, options = {}) {
  if (typeof pkeyHex !== "string" || !/^[0-9a-fA-F]+$/.test(pkeyHex)) {
    throw new Error("PKEY deve ser uma string hexadecimal valida");
  }

  const key = Buffer.from(pkeyHex, "hex");
  const algorithm = resolveAesAlgorithmFromKeyLength(key.length);

  const clearPinBlockHex = buildIso4ClearPinBlock(pin, pan, options.randomHex);
  const clearPinBlock = Buffer.from(clearPinBlockHex, "hex");

  const cipher = crypto.createCipheriv(algorithm, key, null);
  cipher.setAutoPadding(false);

  let encrypted = cipher.update(clearPinBlock);
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return {
    clearPinBlockHex,
    encryptedPinBlockHex: encrypted.toString("hex").toUpperCase(),
    encryptedPinBlockBase64: encrypted.toString("base64"),
  };
}

/**
 * Decripta um PIN block ISO-4 usando PKEY AES (ECB sem padding).
 * @param {string} encryptedPinBlock - PIN block criptografado (hex ou base64)
 * @param {string} pan - PAN do cartao
 * @param {string} pkeyHex - Chave AES em hexadecimal
 * @param {Object} options - Opcoes de entrada
 * @param {"hex"|"base64"} options.inputEncoding - Encoding de encryptedPinBlock (default: "hex")
 * @returns {{pin: string, clearPinBlockHex: string, extractedRandomHex: string}}
 */
function decryptIso4PinBlock(encryptedPinBlock, pan, pkeyHex, options = {}) {
  validatePan(pan);

  if (
    typeof encryptedPinBlock !== "string" ||
    encryptedPinBlock.trim().length === 0
  ) {
    throw new Error("encryptedPinBlock deve ser uma string nao vazia");
  }

  if (typeof pkeyHex !== "string" || !/^[0-9a-fA-F]+$/.test(pkeyHex)) {
    throw new Error("PKEY deve ser uma string hexadecimal valida");
  }

  const inputEncoding = options.inputEncoding || "hex";
  if (!["hex", "base64"].includes(inputEncoding)) {
    throw new Error("inputEncoding deve ser 'hex' ou 'base64'");
  }

  const key = Buffer.from(pkeyHex, "hex");
  const algorithm = resolveAesAlgorithmFromKeyLength(key.length);

  const encrypted =
    inputEncoding === "hex"
      ? Buffer.from(encryptedPinBlock, "hex")
      : Buffer.from(encryptedPinBlock, "base64");

  if (encrypted.length !== 16) {
    throw new Error("PIN block criptografado deve ter 16 bytes");
  }

  const decipher = crypto.createDecipheriv(algorithm, key, null);
  decipher.setAutoPadding(false);

  let clear = decipher.update(encrypted);
  clear = Buffer.concat([clear, decipher.final()]);

  const clearPinBlockHex = clear.toString("hex").toUpperCase();

  const panWithoutCheckDigit = pan.slice(0, -1);
  const pan12RightMost = panWithoutCheckDigit.slice(-12);
  const panField = `00000000000000000000${pan12RightMost}`;
  const pinField = xorHexNibbles(clearPinBlockHex, panField);

  if (pinField[0] !== "4") {
    throw new Error("Formato de PIN block invalido para ISO-4");
  }

  const pinLength = parseInt(pinField[1], 16);
  if (Number.isNaN(pinLength) || pinLength < 4 || pinLength > 12) {
    throw new Error("Tamanho de PIN invalido no PIN block");
  }

  const pin = pinField.slice(2, 2 + pinLength);
  if (!/^\d+$/.test(pin)) {
    throw new Error("PIN extraido contem caracteres invalidos");
  }

  return {
    pin,
    clearPinBlockHex,
    extractedRandomHex: pinField.slice(16),
  };
}

module.exports = {
  buildIso4ClearPinBlock,
  encryptIso4PinBlock,
  decryptIso4PinBlock,
};

const PIN = "123456";
const PAN = "4761739001010119";
const PKEY_HEX = "A0B0C0D0E0F000102030405060708090";
const ENCRYPTED_PIN_BLOCK_HEX = "6DDF70C46D8D2C69013479A4AC5BBC40";

const result = encryptIso4PinBlock(PIN, PAN, PKEY_HEX, {
  randomHex: "0123456789ABCDEF",
});
console.log("Clear PIN Block (Hex):", result.clearPinBlockHex);
console.log("Encrypted PIN Block (Hex):", result.encryptedPinBlockHex);

const decrypted = decryptIso4PinBlock(ENCRYPTED_PIN_BLOCK_HEX, PAN, PKEY_HEX);
console.log(
  "Clear PIN Block (Hex) after decryption:",
  decrypted.clearPinBlockHex,
);
console.log("Decrypted PIN:", decrypted.pin);
