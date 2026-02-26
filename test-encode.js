const TR31Decoder = require("./tr31-decrypt");

console.log("=".repeat(60));
console.log("TESTE DE CODIFICAÇÃO TR-31");
console.log("=".repeat(60));

// KEK (Key Encryption Key) - 32 bytes para AES-256
const kek = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";

// Criar instância do decoder
const decoder = new TR31Decoder(kek);

// Chave a ser protegida (exemplo: chave de 16 bytes)
const keyToProtect = "0123456789ABCDEFFEDCBA9876543210";

console.log("\n1. CODIFICANDO BLOCO TR-31");
console.log("-".repeat(60));
console.log(`KEK: ${kek}`);
console.log(`Chave a proteger: ${keyToProtect}`);

// Codificar com opções padrão (AES-CBC)
const keyBlock1 = decoder.encode(keyToProtect);

console.log("\n2. DECODIFICANDO O BLOCO CRIADO");
console.log("-".repeat(60));

// Decodificar o bloco criado para verificar
const decoded1 = decoder.decode(keyBlock1);
console.log(`\nChave recuperada: ${decoded1.decryptedData}`);

// Remover padding da chave recuperada
const decryptedBuffer = Buffer.from(decoded1.decryptedData, "hex");
const unpaddedKey = decoder.removePadding(decryptedBuffer);
console.log(`Chave sem padding: ${unpaddedKey.toString("hex").toUpperCase()}`);

// Verificar se a chave recuperada é igual à original
const match =
  unpaddedKey.toString("hex").toUpperCase() === keyToProtect.toUpperCase();
console.log(
  `\n✓ Verificação: ${match ? "SUCESSO - Chaves são iguais!" : "ERRO - Chaves diferentes!"}`,
);

console.log("\n" + "=".repeat(60));
console.log("3. TESTANDO DIFERENTES CONFIGURAÇÕES");
console.log("=".repeat(60));

// Teste com TDES-CBC
console.log("\n--- TDES-CBC com MAC de 4 bytes ---");
const keyBlock2 = decoder.encode(keyToProtect, {
  algorithm: "T",
  versionId: "D",
  keyUsage: "P0", // PIN Encryption
  modeOfUse: "B", // Both encrypt and decrypt
  macLength: 4,
});

// Teste com AES-ECB
console.log("\n--- AES-ECB com MAC de 16 bytes ---");
const keyBlock3 = decoder.encode(keyToProtect, {
  algorithm: "A",
  versionId: "B",
  keyUsage: "D0", // Data Encryption
  modeOfUse: "E", // Encrypt only
  macLength: 16,
  exportability: "N", // Non-exportable
});

console.log("\n" + "=".repeat(60));
console.log("TESTES CONCLUÍDOS!");
console.log("=".repeat(60));
