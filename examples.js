const TR31Decoder = require("./TR31Decoder");

/**
 * EXEMPLO AVANÇADO DE USO DO TR-31 DECODER
 *
 * Este arquivo demonstra diferentes casos de uso e explica
 * os componentes do formato TR-31.
 */

// ============================================
// ENTENDENDO O FORMATO TR-31
// ============================================

/*
Um bloco TR-31 tem a seguinte estrutura:

1. HEADER (16 bytes ASCII): Contém metadados sobre a chave
   - Version ID (1 byte): 'A', 'B', 'C', 'D', etc.
   - Length (4 bytes): Comprimento total em caracteres hex
   - Key Usage (2 bytes): Como a chave pode ser usada
   - Algorithm (1 byte): T=TDES, A=AES
   - Mode of Use (1 byte): E=Encrypt, D=Decrypt, B=Both
   - Key Version (2 bytes): Versão da chave
   - Exportability (1 byte): E=Exportable, N=Non-exportable
   - Optional Blocks (2 bytes): Número de blocos opcionais
   - Reserved (2 bytes): Para uso futuro

2. DADOS CRIPTOGRAFADOS: A chave propriamente dita, criptografada com a KEK

3. MAC (4 bytes): Message Authentication Code para verificar integridade
*/

// ============================================
// EXEMPLO 1: Uso Básico
// ============================================

function exemplo1() {
  console.log("\n═══════════════════════════════════════════");
  console.log("  EXEMPLO 1: Decriptação Básica");
  console.log("═══════════════════════════════════════════\n");

  const KEK = "000102030405060708090A0B0C0D0E0F";
  const keyBlock =
    "D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4";

  try {
    const decoder = new TR31Decoder(KEK);
    const result = decoder.decode(keyBlock);

    console.log("✓ Chave decriptada com sucesso!");
    console.log("Resultado:", result.decryptedData);

    return result;
  } catch (error) {
    console.error("❌ Erro:", error.message);
    return null;
  }
}

// ============================================
// EXEMPLO 2: Análise Detalhada do Header
// ============================================

function exemplo2() {
  console.log("\n═══════════════════════════════════════════");
  console.log("  EXEMPLO 2: Análise Detalhada do Header");
  console.log("═══════════════════════════════════════════\n");

  const KEK = "000102030405060708090A0B0C0D0E0F";
  const keyBlock =
    "D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4";

  try {
    const decoder = new TR31Decoder(KEK);
    const result = decoder.decode(keyBlock);

    console.log("📋 ANÁLISE DO HEADER:");
    console.log("─────────────────────────────────────────");
    console.log(`Versão: ${result.header.versionId}`);
    console.log(`  → Versão do formato TR-31`);
    console.log();

    console.log(`Uso da Chave: ${result.header.keyUsage}`);
    console.log(`  → D0 = Data Encryption (Criptografia de Dados)`);
    console.log();

    console.log(`Algoritmo: ${result.header.algorithm}`);
    console.log(`  → A = AES (Advanced Encryption Standard)`);
    console.log();

    console.log(`Modo de Operação: ${result.header.modeOfUse}`);
    console.log(`  → D = Decrypt Only (Apenas Decriptação)`);
    console.log();

    console.log(`Exportabilidade: ${result.header.exportability}`);
    console.log(`  → E = Exportable (Pode ser exportada)`);
    console.log();

    return result;
  } catch (error) {
    console.error("❌ Erro:", error.message);
    return null;
  }
}

// ============================================
// EXEMPLO 3: Verificação de Integridade (MAC)
// ============================================

function exemplo3() {
  console.log("\n═══════════════════════════════════════════");
  console.log("  EXEMPLO 3: Verificação de Integridade");
  console.log("═══════════════════════════════════════════\n");

  const KEK = "000102030405060708090A0B0C0D0E0F";
  const keyBlock =
    "D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4";

  try {
    const decoder = new TR31Decoder(KEK);
    const result = decoder.decode(keyBlock);

    console.log("🔐 VERIFICAÇÃO DE INTEGRIDADE (MAC):");
    console.log("─────────────────────────────────────────");
    console.log(`MAC Recebido: ${result.mac}`);
    console.log(`MAC Válido: ${result.macValid ? "✓ SIM" : "✗ NÃO"}`);
    console.log();

    if (result.macValid) {
      console.log("✓ O bloco TR-31 está íntegro e não foi adulterado.");
      console.log("✓ A KEK utilizada é a correta.");
    } else {
      console.log("⚠ Atenção: A verificação do MAC falhou.");
      console.log("  Possíveis causas:");
      console.log("  - KEK incorreta");
      console.log("  - Bloco corrompido ou adulterado");
      console.log("  - Método de cálculo do MAC diferente");
    }

    return result;
  } catch (error) {
    console.error("❌ Erro:", error.message);
    return null;
  }
}

// ============================================
// EXEMPLO 4: Tratamento de Erros
// ============================================

function exemplo4() {
  console.log("\n═══════════════════════════════════════════");
  console.log("  EXEMPLO 4: Tratamento de Erros");
  console.log("═══════════════════════════════════════════\n");

  // Teste com KEK inválida
  console.log("Teste 1: KEK com tamanho inválido");
  try {
    const decoder = new TR31Decoder("0102030405"); // KEK muito curta
    console.log("✗ Deveria ter lançado erro!");
  } catch (error) {
    console.log("✓ Erro capturado:", error.message);
  }

  // Teste com bloco inválido
  console.log("\nTeste 2: Key Block inválido");
  try {
    const decoder = new TR31Decoder("000102030405060708090A0B0C0D0E0F");
    decoder.decode("BLOCOMUITO CURTO"); // Bloco inválido
    console.log("✗ Deveria ter lançado erro!");
  } catch (error) {
    console.log("✓ Erro capturado:", error.message);
  }

  console.log("\n✓ Tratamento de erros funcionando corretamente!");
}

// ============================================
// EXEMPLO 5: Processamento em Lote
// ============================================

function exemplo5() {
  console.log("\n═══════════════════════════════════════════");
  console.log("  EXEMPLO 5: Processamento em Lote");
  console.log("═══════════════════════════════════════════\n");

  const KEK = "000102030405060708090A0B0C0D0E0F";

  // Lista de blocos para processar
  const blocos = [
    {
      nome: "Bloco Principal",
      keyBlock:
        "D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4",
    },
    // Adicione mais blocos aqui conforme necessário
  ];

  const decoder = new TR31Decoder(KEK);
  const resultados = [];

  console.log(`📦 Processando ${blocos.length} bloco(s)...\n`);

  blocos.forEach((item, index) => {
    console.log(`─── Bloco ${index + 1}: ${item.nome} ───`);
    try {
      const result = decoder.decode(item.keyBlock);
      resultados.push({
        nome: item.nome,
        sucesso: true,
        chave: result.decryptedData,
        macValido: result.macValid,
      });
      console.log(`✓ Sucesso - MAC válido: ${result.macValid}`);
    } catch (error) {
      resultados.push({
        nome: item.nome,
        sucesso: false,
        erro: error.message,
      });
      console.log(`✗ Erro: ${error.message}`);
    }
    console.log();
  });

  console.log(
    `✓ Processamento concluído: ${resultados.filter((r) => r.sucesso).length}/${blocos.length} bem-sucedidos`,
  );

  return resultados;
}

// ============================================
// EXECUTAR EXEMPLOS
// ============================================

if (require.main === module) {
  console.log("\n╔═══════════════════════════════════════════╗");
  console.log("║   TR-31 DECODER - EXEMPLOS AVANÇADOS     ║");
  console.log("╚═══════════════════════════════════════════╝");

  // Executar todos os exemplos
  exemplo1();
  exemplo2();
  exemplo3();
  exemplo4();
  exemplo5();

  console.log("\n═══════════════════════════════════════════");
  console.log("  Todos os exemplos foram executados!");
  console.log("═══════════════════════════════════════════\n");
}

// Exportar funções para uso em outros módulos
module.exports = {
  exemplo1,
  exemplo2,
  exemplo3,
  exemplo4,
  exemplo5,
};
