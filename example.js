const TR31Decoder = require("./tr31-decrypt");

/**
 * Aplicação principal para decriptografia de blocos TR-31
 */

// Dados do exemplo
const KEK = "000102030405060708090A0B0C0D0E0F";
const KEY_BLOCK =
  "D0112K0TB00E00003783296648F2B8759C57B0C9834B8BAA1B538BD602798714EEC9759AF417AB4A72BCAE6B96DA24B9932327D625E18F50";
const ENCRYPTED_CARD_DATA =
  "Rjdmv4OkbMZ+Y7B49UDyP75xdd669XGmLD2qk2sT++jZ5xgXXZR94hUyheKUEDwxWhGwOltPJmc8EmR+75Hx9Fb9BROjuecS3ra39hQ9JffbgKBNpa9J8kfospQDHVa2eOft1HnzBiEwNxg6EsQ2rWa1sStmDc/6XbsvV3XjO143KT9LxJFsbuLG2bww6qdvxR9j9b3oBsY8f3RS1fx7wlHCmXw7vkZn+CdTb1lzrf2iBcAi2kDfgZebokkNxXmX";

console.log("===========================================");
console.log("    TR-31 KEY BLOCK DECODER");
console.log("===========================================");
console.log(`\nKEK (Key Encryption Key): ${KEK}`);
console.log(`Key Block: ${KEY_BLOCK}`);
console.log("\n===========================================\n");

try {
  // Criar instância do decoder
  const decoder = new TR31Decoder(KEK);

  // Decodificar o bloco
  const result = decoder.decode(KEY_BLOCK);
  const unpaddedKey = decoder.removePadding(
    Buffer.from(result.decryptedData, "hex"),
  );

  // Exibir resultado final
  console.log("\n===========================================");
  console.log("    RESULTADO FINAL");
  console.log("===========================================");
  console.log("\nChave Decriptada (HEX):");
  console.log(unpaddedKey.toString("hex").toUpperCase());
  console.log("\n===========================================\n");
} catch (error) {
  console.error("\n❌ ERRO:", error.message);
  console.error("\nDetalhes:", error.stack);
  process.exit(1);
}
