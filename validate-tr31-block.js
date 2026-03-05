/**
 * Script para validar e analisar blocos TR-31
 */

const TR31Decoder = require("./tr31-decrypt");

// Configuração
const KEK_HEX = "000102030405060708090A0B0C0D0E0F";
const TR31_BLOCK =
  "D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4";

console.log("🔍 Validação de Bloco TR-31");
console.log("═══════════════════════════════════════════════════════\n");

console.log("📋 Dados de entrada:");
console.log(`   KEK: ${KEK_HEX}`);
console.log(`   TR-31 Block: ${TR31_BLOCK}`);
console.log(`   Tamanho do bloco: ${TR31_BLOCK.length} caracteres`);
console.log();

// Analisar header
const header = TR31_BLOCK.substring(0, 16);
console.log("📄 Header (primeiros 16 caracteres):");
console.log(`   ${header}`);
console.log();

// Decodificar header
const versionId = header[0];
const lengthHex = header.substring(1, 5);
const lengthDecimal = parseInt(lengthHex, 10);
const keyUsage = header.substring(5, 7);
const algorithm = header[7];
const modeOfUse = header[8];
const keyVersion = header.substring(9, 11);
const exportability = header[11];
const numOptionalBlocks = header.substring(12, 14);
const reserved = header.substring(14, 16);

console.log("🔎 Análise do Header:");
console.log(`   Version ID: ${versionId}`);
console.log(`   Length: ${lengthHex} (${lengthDecimal} caracteres decimais)`);
console.log(`   Key Usage: ${keyUsage}`);
console.log(`   Algorithm: ${algorithm} (${algorithm === 'T' ? 'TDES' : algorithm === 'A' ? 'AES' : 'Desconhecido'})`);
console.log(`   Mode of Use: ${modeOfUse}`);
console.log(`   Key Version: ${keyVersion}`);
console.log(`   Exportability: ${exportability}`);
console.log(`   Optional Blocks: ${numOptionalBlocks}`);
console.log(`   Reserved: ${reserved}`);
console.log();

// Verificar tamanho
const expectedLength = lengthDecimal;
const actualLength = TR31_BLOCK.length;

console.log("📏 Verificação de Tamanho:");
console.log(`   Esperado (do header): ${expectedLength} caracteres`);
console.log(`   Real: ${actualLength} caracteres`);

if (expectedLength !== actualLength) {
  console.log(`   ❌ ERRO: Tamanho não corresponde! Faltam ${expectedLength - actualLength} caracteres`);
} else {
  console.log(`   ✅ Tamanho correto`);
}
console.log();

// Analisar dados após header
const remainingData = TR31_BLOCK.substring(16);
const remainingBytes = remainingData.length / 2;

console.log("📦 Dados após o header:");
console.log(`   ${remainingData.substring(0, 80)}${remainingData.length > 80 ? '...' : ''}`);
console.log(`   Tamanho: ${remainingData.length} caracteres hex (${remainingBytes} bytes)`);
console.log();

// Tentar decodificar localmente
console.log("🔓 Tentando decodificar localmente...");
console.log();

try {
  const decoder = new TR31Decoder(KEK_HEX);
  const result = decoder.decode(TR31_BLOCK);
  
  console.log("✅ Decodificação local bem-sucedida!");
  console.log();
  console.log("📊 Resultado:");
  console.log(JSON.stringify(result, null, 2));
  
  // Remover padding
  const unpaddedKey = decoder.removePadding(
    Buffer.from(result.decryptedData, "hex"),
  );
  
  console.log();
  console.log("🔑 Chave decriptada (sem padding):");
  console.log(`   ${unpaddedKey.toString("hex").toUpperCase()}`);
  console.log();
  
  console.log("═══════════════════════════════════════════════════════");
  console.log("✨ Diagnóstico:");
  console.log("   O bloco TR-31 é VÁLIDO localmente.");
  console.log("   O problema pode ser:");
  console.log("   1. AWS espera formato diferente do TR-31");
  console.log("   2. A KEK importada na AWS não é a mesma");
  console.log("   3. AWS não suporta este tipo de bloco TR-31");
  console.log("═══════════════════════════════════════════════════════");
  
} catch (error) {
  console.log("❌ Falha na decodificação local!");
  console.log(`   Erro: ${error.message}`);
  console.log();
  console.log("═══════════════════════════════════════════════════════");
  console.log("✨ Diagnóstico:");
  console.log("   O bloco TR-31 está INVÁLIDO ou CORROMPIDO.");
  console.log("   Ações recomendadas:");
  console.log("   1. Verificar se a KEK está correta");
  console.log("   2. Verificar se o bloco TR-31 está completo");
  console.log("   3. Gerar um novo bloco TR-31 válido");
  console.log("═══════════════════════════════════════════════════════");
  
  console.error();
  console.error("Stack trace:");
  console.error(error.stack);
}
