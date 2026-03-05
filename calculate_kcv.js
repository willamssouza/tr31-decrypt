const crypto = require("crypto");

function calculateKCV_AES_CBC(key) {
  // Key pode ser 16, 24 ou 32 bytes (128, 192 ou 256 bits)
  const cipher = crypto.createCipheriv(
    "aes-128-cbc",
    key,
    Buffer.alloc(16, 0x00),
  ); // IV de 16 bytes preenchido com zeros
  cipher.setAutoPadding(false);

  const zeros = Buffer.alloc(16, 0x00);
  const encrypted = cipher.update(zeros);

  // Retorna os 3 primeiros bytes em hexadecimal
  return encrypted.slice(0, 3).toString("hex").toUpperCase();
}

function calculateKCV_AES_ECB(key) {
  // Key pode ser 16, 24 ou 32 bytes (128, 192 ou 256 bits)
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null); // IV de 16 bytes preenchido com zeros
  cipher.setAutoPadding(false);

  const zeros = Buffer.alloc(16, 0);
  const encrypted = Buffer.concat([cipher.update(zeros), cipher.final()]);

  // Retorna os 3 primeiros bytes em hexadecimal
  return encrypted.slice(0, 3).toString("hex").toUpperCase();
}

// BE7ED6

const kekAES = Buffer.from("000102030405060708090A0B0C0D0E0F", "hex"); // 16 bytes
console.log("CardDataKCV (AES-ECB):", calculateKCV_AES_ECB(kekAES));
console.log("CardDataKCV (AES-CBC):", calculateKCV_AES_CBC(kekAES));

const pinAES = Buffer.from("A0B0C0D0E0F000102030405060708090", "hex"); // 16 bytes
console.log("PINDataKCV (AES-ECB):", calculateKCV_AES_ECB(pinAES));
console.log("PINDataKCV (AES-CBC):", calculateKCV_AES_CBC(pinAES));
