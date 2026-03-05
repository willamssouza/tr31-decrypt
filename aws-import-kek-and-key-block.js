/**
 * Script simplificado para importar KEK no AWS Payment Cryptography
 * usando RSA-AES Key Wrap e depois importar chave do bloco TR-31 usando a KEK importada.
 *
 * Pré-requisitos:
 * npm install @aws-sdk/client-payment-cryptography @aws-sdk/client-payment-cryptography-data
 */

const {
  PaymentCryptographyClient,
  ImportKeyCommand,
  GetParametersForImportCommand,
  GetKeyCommand,
} = require("@aws-sdk/client-payment-cryptography");

const crypto = require("crypto");

// Configuração
const REGION = "us-east-1";
const KEK_HEX = "000102030405060708090A0B0C0D0E0F";
const TR31_BLOCK =
  "D0056D0AE01E0000868D79BD49A5681CFAE908AD51300BA0E39A58F2203E325C38D669FC3D4A6F21C0454017C82FD34B";
const KEK_ARN =
  "arn:aws:payment-cryptography:us-east-1:839834288637:key/laxd576r5b55k5vs";

/**
 * Passo 1: Importar KEK usando RSA-AES Key Wrap
 */
async function importKEK(client, kekHex) {
  console.log("🔐 Passo 1: Validando KEK antes da importação...");

  // Validar tamanho da KEK
  const kekBytes = kekHex.length / 2;
  let keyAlgorithm;

  if (kekBytes === 16) {
    keyAlgorithm = "AES_128";
    console.log("   ✅ Algoritmo detectado: AES_128 (128 bits)");
  } else if (kekBytes === 24) {
    keyAlgorithm = "AES_192";
    console.log("   ✅ Algoritmo detectado: AES_192 (192 bits)");
  } else if (kekBytes === 32) {
    keyAlgorithm = "AES_256";
    console.log("   ✅ Algoritmo detectado: AES_256 (256 bits)");
  } else {
    console.error("   ❌ Tamanho inválido! Deve ser 16, 24 ou 32 bytes");
    throw new Error(
      `KEK tem tamanho inválido: ${kekBytes} bytes. Esperado: 16, 24 ou 32 bytes`,
    );
  }

  console.log("\n🔐 Passo 2: Obtendo parâmetros de importação da AWS...");

  // Obter certificado público da AWS para importação
  const paramsCommand = new GetParametersForImportCommand({
    KeyMaterialType: "KEY_CRYPTOGRAM",
    WrappingKeyAlgorithm: "RSA_4096",
  });

  const params = await client.send(paramsCommand);

  console.log("📜 Certificado de importação obtido");
  console.log("📋 Import Token:", params.ImportToken.substring(0, 20) + "...");
  console.log(
    "📋 Wrapping Key Certificate:",
    params.WrappingKeyCertificate.substring(0, 40) + "...\n",
  );

  // Encriptar KEK com o certificado público da AWS
  console.log("\n🔒 Passo 3: Encriptando KEK com certificado AWS...");
  const wrappedKEK = wrapKeyWithRSAAES(kekHex, params.WrappingKeyCertificate);

  console.log(
    "🔐 Key Cryptogram gerado (primeiros 40 chars):",
    wrappedKEK.substring(0, 40),
  );
  console.log("📏 Tamanho do Key Cryptogram:", wrappedKEK.length, "caracteres");

  // Importar KEK
  console.log("\n📥 Passo 4: Importando KEK...");
  console.log("   Algoritmo declarado:", keyAlgorithm);

  const importCommand = new ImportKeyCommand({
    KeyMaterial: {
      KeyCryptogram: {
        ImportToken: params.ImportToken,
        WrappedKeyCryptogram: wrappedKEK,
        WrappingSpec: "RSA_OAEP_SHA_256",
        Exportable: true,
        KeyAttributes: {
          KeyAlgorithm: keyAlgorithm, // ← Usa o algoritmo detectado automaticamente
          KeyClass: "SYMMETRIC_KEY",
          KeyUsage: "TR31_K0_KEY_ENCRYPTION_KEY",
          KeyModesOfUse: {
            Encrypt: true,
            Decrypt: true,
            Wrap: true,
            Unwrap: true,
          },
        },
      },
    },
    KeyCheckValueAlgorithm: "ANSI_X9_24",
    Enabled: true,
    Tags: [
      { Key: "Name", Value: "ImportedKEK" },
      { Key: "Source", Value: "TR31Decoder" },
      { Key: "Algorithm", Value: keyAlgorithm },
    ],
  });

  const response = await client.send(importCommand);

  console.log("\n✅ KEK importada com sucesso!");
  console.log("📍 ARN:", response.Key.KeyArn);
  console.log("🔑 Key Check Value:", response.Key.KeyCheckValue);
  console.log("🏷️  Key Usage:", response.Key.KeyAttributes.KeyUsage);
  console.log("🔐 Key Algorithm:", response.Key.KeyAttributes.KeyAlgorithm);

  return response.Key.KeyArn;
}

/**
 * Encriptar chave com RSA-OAEP e preparar Key Cryptogram
 */
function wrapKeyWithRSAAES(keyHex, certificatePem) {
  // Converter HEX para Buffer
  const keyBuffer = Buffer.from(keyHex, "hex");

  console.log("📄 Tipo do certificado recebido:", typeof certificatePem);

  let publicKey;

  try {
    let certToUse = certificatePem;

    // Se é uma string Base64 pura (sem headers PEM), precisa decodificar primeiro
    if (
      typeof certificatePem === "string" &&
      !certificatePem.includes("-----BEGIN CERTIFICATE-----") &&
      /^[A-Za-z0-9+/=\s]+$/.test(certificatePem)
    ) {
      console.log("✓ Decodificando Base64 para obter o certificado PEM...");
      certToUse = Buffer.from(certificatePem, "base64").toString("utf8");
    }

    // Criar chave pública
    if (
      typeof certToUse === "string" &&
      certToUse.includes("-----BEGIN CERTIFICATE-----")
    ) {
      console.log("✓ Criando chave pública a partir do certificado PEM");
      publicKey = crypto.createPublicKey({
        key: certToUse,
        format: "pem",
      });
    } else {
      throw new Error("Formato de certificado não reconhecido");
    }

    console.log("✅ Chave pública extraída com sucesso");
  } catch (error) {
    console.error(
      "❌ Erro ao extrair chave pública do certificado:",
      error.message,
    );
    throw new Error(
      "Não foi possível processar o certificado: " + error.message,
    );
  }

  // Encriptar usando RSA-OAEP SHA-256
  const encrypted = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    keyBuffer,
  );

  // Retornar em HEX (AWS espera HEX)
  return encrypted.toString("hex").toUpperCase();
}

/**
 * Passo 2: Importar chave do bloco TR-31
 */
async function importTR31Key(client, tr31Block, kekArn) {
  console.log("\n\n📦 Passo 4: Importando chave do bloco TR-31...");
  console.log("🔗 Usando KEK:", kekArn);
  console.log("📄 TR-31 Block:", tr31Block.substring(0, 40) + "...");

  const importCommand = new ImportKeyCommand({
    KeyMaterial: {
      Tr31KeyBlock: {
        WrappingKeyIdentifier: kekArn,
        WrappedKeyBlock: tr31Block,
      },
    },
    Enabled: true,
    Exportable: true,
    Tags: [
      { Key: "Name", Value: "ImportedFromTR31" },
      { Key: "Source", Value: "TR31Block" },
    ],
  });

  const response = await client.send(importCommand);

  console.log("\n✅ Chave TR-31 importada com sucesso!");
  console.log("📍 ARN:", response.Key.KeyArn);
  console.log("🔑 Key Check Value:", response.Key.KeyCheckValue);
  console.log("🏷️  Key Usage:", response.Key.KeyAttributes.KeyUsage);
  console.log("🔐 Key Algorithm:", response.Key.KeyAttributes.KeyAlgorithm);

  return response.Key.KeyArn;
}

/**
 * Verificar detalhes de uma chave
 */
async function getKeyDetails(client, keyArn) {
  console.log("\n\n🔍 Verificando detalhes da chave...");

  const getKeyCommand = new GetKeyCommand({
    KeyIdentifier: keyArn,
  });

  const response = await client.send(getKeyCommand);

  console.log("\n📊 Detalhes da Chave:");
  console.log(JSON.stringify(response.Key, null, 2));

  return response.Key;
}

/**
 * Função principal
 */
async function main() {
  console.log("🚀 AWS Payment Cryptography - Importação KEK e TR-31");
  console.log("    (Método simplificado com RSA-AES Key Wrap)\n");
  console.log("═══════════════════════════════════════════════════════\n");

  const client = new PaymentCryptographyClient({ region: REGION });

  try {
    // Importar KEK
    //const kekArn = await importKEK(client, KEK_HEX);
    const kekArn =
      "arn:aws:payment-cryptography:us-east-1:839834288637:key/ubnefqhww5ughxv6";

    // Importar chave do TR-31
    const keyArn = await importTR31Key(client, TR31_BLOCK, kekArn);

    // Verificar detalhes
    await getKeyDetails(client, keyArn);

    console.log("\n\n═══════════════════════════════════════════════════════");
    console.log("✨ Processo concluído com sucesso!");
    console.log("═══════════════════════════════════════════════════════");
    console.log("\n📝 ARNs criados:");
    console.log("   KEK:", kekArn);
    console.log("   Chave:", keyArn);
  } catch (error) {
    console.error("\n❌ Erro durante importação:", error);

    if (error.name === "ValidationException") {
      console.error("\n💡 Dica: Verifique se:");
      console.error("   - A KEK está no formato correto");
      console.error("   - O bloco TR-31 é válido");
      console.error("   - O checksum do TR-31 está correto");
    }

    process.exit(1);
  }
}

// Executar
if (require.main === module) {
  main();
}

module.exports = {
  importKEK,
  importTR31Key,
  getKeyDetails,
};
