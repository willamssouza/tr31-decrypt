const crypto = require("crypto");

/**
 * Classe para decriptografia de blocos de chave TR-31
 * Baseado no padrão ANSI X9 TR-31
 */
class TR31Decoder {
  constructor(kek) {
    if (!kek || typeof kek !== "string") {
      throw new Error("KEK (Key Encryption Key) é obrigatória");
    }
    this.kek = Buffer.from(kek, "hex");

    // Validação do tamanho da KEK
    if (![16, 24, 32].includes(this.kek.length)) {
      throw new Error("KEK deve ter 16, 24 ou 32 bytes (128, 192 ou 256 bits)");
    }
  }

  /**
   * Decodifica um bloco TR-31
   * @param {string} keyBlock - Bloco TR-31 em formato hexadecimal
   * @returns {Object} Objeto com informações do bloco decodificado
   */
  decode(keyBlock) {
    if (!keyBlock || typeof keyBlock !== "string") {
      throw new Error("KeyBlock é obrigatório");
    }

    // O bloco TR-31 completo em hex
    // O header são os primeiros 16 caracteres (não em hex, mas caracteres normais do keyBlock)
    // Exemplo: D0112D0AD00E0000 = 16 caracteres formam o header
    const header = keyBlock.substring(0, 16);

    // O restante do bloco após o header
    const remainingHex = keyBlock.substring(16);

    // Converter apenas o restante (dados + MAC) para buffer
    const remainingBuffer = Buffer.from(remainingHex, "hex");

    // Análise do header
    const headerInfo = this.parseHeader(header);

    console.log("\n=== INFORMAÇÕES DO HEADER ===");
    console.log(`Versão ID: ${headerInfo.versionId}`);
    console.log(`Comprimento total: ${headerInfo.length}`);
    console.log(`Uso da chave: ${headerInfo.keyUsage}`);
    console.log(`Algoritmo: ${headerInfo.algorithm}`);
    console.log(`Modo de operação: ${headerInfo.modeOfUse}`);
    console.log(`Versão da chave: ${headerInfo.keyVersion}`);
    console.log(`Exportabilidade: ${headerInfo.exportability}`);
    console.log(`Blocos opcionais: ${headerInfo.optionalBlocks}`);
    console.log(`Reservado: ${headerInfo.reserved}`);

    // Tentar decriptar com diferentes tamanhos de MAC
    // O padrão TR-31 permite MACs de 4, 6, 8, ou 16 bytes
    const possibleMacLengths = [4, 8, 16, 6];
    let decryptedData = null;
    let encryptedData = null;
    let mac = null;
    let lastError = null;

    for (const macLength of possibleMacLengths) {
      const encryptedDataLength = remainingBuffer.length - macLength;

      // Verificar se o tamanho resultante é válido
      if (encryptedDataLength <= 0) continue;

      // Para AES, os dados devem ser múltiplos de 16
      // Para TDES, os dados devem ser múltiplos de 8
      const blockSize = headerInfo.algorithm === "A" ? 16 : 8;
      if (encryptedDataLength % blockSize !== 0) continue;

      encryptedData = remainingBuffer.slice(0, encryptedDataLength);
      mac = remainingBuffer.slice(encryptedDataLength);

      console.log(`\n=== TENTANDO COM MAC DE ${macLength} BYTES ===`);
      console.log(`Dados criptografados: ${encryptedDataLength} bytes`);

      try {
        decryptedData = this.decryptData(encryptedData, headerInfo);
        console.log(`✓ Decriptação bem-sucedida com MAC de ${macLength} bytes`);
        break;
      } catch (error) {
        lastError = error;
        console.log(`✗ Falhou com MAC de ${macLength} bytes: ${error.message}`);
        continue;
      }
    }

    if (!decryptedData) {
      throw new Error(
        `Não foi possível decriptar com nenhum tamanho de MAC. Último erro: ${lastError?.message}`,
      );
    }

    // Calcular tamanhos finais
    const macLength = mac.length;

    console.log("\n=== DADOS CRIPTOGRAFADOS ===");
    console.log(`Tamanho: ${encryptedData.length} bytes`);
    console.log(`Hex: ${encryptedData.toString("hex").toUpperCase()}`);
    console.log(`\nMAC: ${mac.toString("hex").toUpperCase()}`);

    console.log("\n=== DADOS DECRIPTADOS ===");
    console.log(`Tamanho: ${decryptedData.length} bytes`);
    console.log(`Hex: ${decryptedData.toString("hex").toUpperCase()}`);
    console.log(`ASCII: ${this.toReadableAscii(decryptedData)}`);

    return {
      header: headerInfo,
      encryptedData: encryptedData.toString("hex"),
      decryptedData: decryptedData.toString("hex"),
      decryptedDataAscii: this.toReadableAscii(decryptedData),
      mac: mac.toString("hex"),
    };
  }

  /**
   * Parse do header TR-31 (16 bytes)
   */
  parseHeader(header) {
    return {
      versionId: header.substring(0, 1), // Byte 0: Version ID
      length: header.substring(1, 5), // Bytes 1-4: Length (4 dígitos)
      keyUsage: header.substring(5, 7), // Bytes 5-6: Key Usage
      algorithm: header.substring(7, 8), // Byte 7: Algorithm
      modeOfUse: header.substring(8, 9), // Byte 8: Mode of Use
      keyVersion: header.substring(9, 11), // Bytes 9-10: Key Version
      exportability: header.substring(11, 12), // Byte 11: Exportability
      optionalBlocks: header.substring(12, 14), // Bytes 12-13: Number of optional blocks
      reserved: header.substring(14, 16), // Bytes 14-15: Reserved
    };
  }

  /**
   * Decripta os dados usando TDES-ECB, TDES-CBC ou AES
   */
  decryptData(encryptedData, headerInfo) {
    try {
      // Verificar o algoritmo do header
      if (headerInfo.algorithm === "A") {
        // AES
        if (headerInfo.versionId === "D") {
          return this.decryptAES_CBC(encryptedData);
        } else {
          return this.decryptAES_ECB(encryptedData);
        }
      } else if (headerInfo.algorithm === "T") {
        // TDES
        if (headerInfo.versionId === "D") {
          return this.decryptTDES_CBC(encryptedData);
        } else {
          return this.decryptTDES_ECB(encryptedData);
        }
      } else {
        throw new Error(`Algoritmo não suportado: ${headerInfo.algorithm}`);
      }
    } catch (error) {
      console.warn(`Erro ao decriptar: ${error.message}`);
      throw error;
    }
  }

  /**
   * Decripta usando TDES no modo ECB
   */
  decryptTDES_ECB(data) {
    const key = this.derive3DESKey(this.kek);
    const decipher = crypto.createDecipheriv("des-ede3", key, null);
    decipher.setAutoPadding(false);

    let decrypted = decipher.update(data);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
  }

  /**
   * Decripta usando TDES no modo CBC
   */
  decryptTDES_CBC(data) {
    const key = this.derive3DESKey(this.kek);
    const iv = Buffer.alloc(8, 0); // IV zerado para TR-31

    const decipher = crypto.createDecipheriv("des-ede3-cbc", key, iv);
    decipher.setAutoPadding(false);

    let decrypted = decipher.update(data);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
  }

  /**
   * Deriva uma chave 3DES de 24 bytes a partir da KEK
   */
  derive3DESKey(kek) {
    if (kek.length === 16) {
      // KEK de 128 bits -> criar chave 3DES (K1 | K2 | K1)
      return Buffer.concat([kek, kek.slice(0, 8)]);
    } else if (kek.length === 24) {
      // KEK já é 3DES
      return kek;
    } else if (kek.length === 32) {
      // KEK de 256 bits -> usar primeiros 24 bytes
      return kek.slice(0, 24);
    }
    throw new Error("Tamanho de KEK não suportado");
  }

  /**
   * Decripta usando AES no modo ECB
   */
  decryptAES_ECB(data) {
    let algorithm;
    if (this.kek.length === 16) {
      algorithm = "aes-128-ecb";
    } else if (this.kek.length === 24) {
      algorithm = "aes-192-ecb";
    } else if (this.kek.length === 32) {
      algorithm = "aes-256-ecb";
    } else {
      throw new Error("Tamanho de KEK não suportado para AES");
    }

    const decipher = crypto.createDecipheriv(algorithm, this.kek, null);
    decipher.setAutoPadding(false);

    let decrypted = decipher.update(data);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
  }

  /**
   * Decripta usando AES no modo CBC
   */
  decryptAES_CBC(data) {
    let algorithm;
    if (this.kek.length === 16) {
      algorithm = "aes-128-cbc";
    } else if (this.kek.length === 24) {
      algorithm = "aes-192-cbc";
    } else if (this.kek.length === 32) {
      algorithm = "aes-256-cbc";
    } else {
      throw new Error("Tamanho de KEK não suportado para AES");
    }

    const iv = Buffer.alloc(16, 0); // IV zerado para TR-31

    const decipher = crypto.createDecipheriv(algorithm, this.kek, iv);
    decipher.setAutoPadding(false);

    let decrypted = decipher.update(data);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
  }

  /**
   * Converte buffer para ASCII legível
   */
  toReadableAscii(buffer) {
    return buffer.toString("ascii").replace(/[\x00-\x1F\x7F-\xFF]/g, ".");
  }

  /**
   * Codifica/criptografa uma chave em formato TR-31
   * @param {string|Buffer} keyData - Dados da chave a serem criptografados (hex string ou Buffer)
   * @param {Object} options - Opções para o bloco TR-31
   * @param {string} options.versionId - Version ID ('D' para CBC, 'B' para ECB) - default: 'D'
   * @param {string} options.keyUsage - Key Usage (ex: 'D0' para Data Encryption) - default: 'D0'
   * @param {string} options.algorithm - Algorithm ('A' para AES, 'T' para TDES) - default: 'A'
   * @param {string} options.modeOfUse - Mode of Use (ex: 'E' para Encrypt) - default: 'E'
   * @param {string} options.keyVersion - Key Version (2 dígitos) - default: '00'
   * @param {string} options.exportability - Exportability ('E' ou 'N') - default: 'E'
   * @param {number} options.macLength - Tamanho do MAC em bytes (4, 8, 16) - default: 8
   * @returns {string} Bloco TR-31 completo em formato hexadecimal
   */
  encode(keyData, options = {}) {
    // Converter keyData para Buffer se for string
    const keyBuffer =
      typeof keyData === "string" ? Buffer.from(keyData, "hex") : keyData;

    // Opções padrão
    const versionId = options.versionId || "D";
    const keyUsage = options.keyUsage || "D0";
    const algorithm = options.algorithm || "A";
    const modeOfUse = options.modeOfUse || "E";
    const keyVersion = options.keyVersion || "00";
    const exportability = options.exportability || "E";
    const macLength = options.macLength || 8;

    // Validações
    if (![4, 8, 16].includes(macLength)) {
      throw new Error("MAC length deve ser 4, 8 ou 16 bytes");
    }

    // Determinar o tamanho do bloco baseado no algoritmo
    const blockSize = algorithm === "A" ? 16 : 8;

    // Adicionar padding aos dados da chave
    const paddedKey = this.addPadding(keyBuffer, blockSize);

    // Criptografar os dados
    const encryptedData = this.encryptData(paddedKey, {
      versionId,
      algorithm,
    });

    // Calcular o comprimento total do bloco TR-31
    // Formato: header (16) + encrypted data + MAC
    const totalLength = 16 + encryptedData.length + macLength;

    // Construir o header (16 caracteres ASCII)
    const header =
      versionId + // 1 byte: Version ID
      totalLength.toString().padStart(4, "0") + // 4 bytes: Length
      keyUsage + // 2 bytes: Key Usage
      algorithm + // 1 byte: Algorithm
      modeOfUse + // 1 byte: Mode of Use
      keyVersion + // 2 bytes: Key Version
      exportability + // 1 byte: Exportability
      "00" + // 2 bytes: Number of optional blocks (00 = nenhum)
      "00"; // 2 bytes: Reserved

    // Calcular o MAC sobre header + dados criptografados
    const dataToMac = Buffer.concat([
      Buffer.from(header, "ascii"),
      encryptedData,
    ]);

    const mac = this.calculateMAC(dataToMac, algorithm, macLength);

    // Montar o bloco TR-31 completo
    const keyBlock =
      header + encryptedData.toString("hex") + mac.toString("hex");

    console.log("\n=== BLOCO TR-31 CRIADO ===");
    console.log(`Header: ${header}`);
    console.log(`Dados originais: ${keyBuffer.toString("hex").toUpperCase()}`);
    console.log(
      `Dados com padding: ${paddedKey.toString("hex").toUpperCase()}`,
    );
    console.log(
      `Dados criptografados: ${encryptedData.toString("hex").toUpperCase()}`,
    );
    console.log(`MAC: ${mac.toString("hex").toUpperCase()}`);
    console.log(`Bloco completo: ${keyBlock.toUpperCase()}`);

    return keyBlock.toUpperCase();
  }

  /**
   * Adiciona padding ISO 9797-1 Method 2 aos dados
   * Padding: 0x80 seguido de 0x00 até completar o tamanho do bloco
   */
  addPadding(data, blockSize) {
    const paddingLength = blockSize - (data.length % blockSize);

    if (paddingLength === blockSize) {
      // Se já está alinhado, adicionar um bloco completo de padding
      const padding = Buffer.alloc(blockSize);
      padding[0] = 0x80;
      return Buffer.concat([data, padding]);
    } else {
      // Adicionar padding necessário
      const padding = Buffer.alloc(paddingLength);
      padding[0] = 0x80;
      return Buffer.concat([data, padding]);
    }
  }

  /**
   * Remove padding ISO 9797-1 Method 2
   */
  removePadding(data) {
    // Procurar pelo último byte 0x80
    for (let i = data.length - 1; i >= 0; i--) {
      if (data[i] === 0x80) {
        // Verificar se todos os bytes após 0x80 são 0x00
        let validPadding = true;
        for (let j = i + 1; j < data.length; j++) {
          if (data[j] !== 0x00) {
            validPadding = false;
            break;
          }
        }
        if (validPadding) {
          return data.slice(0, i);
        }
      }
    }
    // Se não encontrar padding válido, retornar os dados originais
    return data;
  }

  /**
   * Criptografa os dados usando TDES ou AES
   */
  encryptData(data, headerInfo) {
    try {
      if (headerInfo.algorithm === "A") {
        // AES
        if (headerInfo.versionId === "D") {
          return this.encryptAES_CBC(data);
        } else {
          return this.encryptAES_ECB(data);
        }
      } else if (headerInfo.algorithm === "T") {
        // TDES
        if (headerInfo.versionId === "D") {
          return this.encryptTDES_CBC(data);
        } else {
          return this.encryptTDES_ECB(data);
        }
      } else {
        throw new Error(`Algoritmo não suportado: ${headerInfo.algorithm}`);
      }
    } catch (error) {
      console.warn(`Erro ao criptografar: ${error.message}`);
      throw error;
    }
  }

  /**
   * Criptografa usando TDES no modo ECB
   */
  encryptTDES_ECB(data) {
    const key = this.derive3DESKey(this.kek);
    const cipher = crypto.createCipheriv("des-ede3", key, null);
    cipher.setAutoPadding(false);

    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return encrypted;
  }

  /**
   * Criptografa usando TDES no modo CBC
   */
  encryptTDES_CBC(data) {
    const key = this.derive3DESKey(this.kek);
    const iv = Buffer.alloc(8, 0); // IV zerado para TR-31

    const cipher = crypto.createCipheriv("des-ede3-cbc", key, iv);
    cipher.setAutoPadding(false);

    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return encrypted;
  }

  /**
   * Criptografa usando AES no modo ECB
   */
  encryptAES_ECB(data) {
    let algorithm;
    if (this.kek.length === 16) {
      algorithm = "aes-128-ecb";
    } else if (this.kek.length === 24) {
      algorithm = "aes-192-ecb";
    } else if (this.kek.length === 32) {
      algorithm = "aes-256-ecb";
    } else {
      throw new Error("Tamanho de KEK não suportado para AES");
    }

    const cipher = crypto.createCipheriv(algorithm, this.kek, null);
    cipher.setAutoPadding(false);

    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return encrypted;
  }

  /**
   * Criptografa usando AES no modo CBC
   */
  encryptAES_CBC(data) {
    let algorithm;
    if (this.kek.length === 16) {
      algorithm = "aes-128-cbc";
    } else if (this.kek.length === 24) {
      algorithm = "aes-192-cbc";
    } else if (this.kek.length === 32) {
      algorithm = "aes-256-cbc";
    } else {
      throw new Error("Tamanho de KEK não suportado para AES");
    }

    const iv = Buffer.alloc(16, 0); // IV zerado para TR-31

    const cipher = crypto.createCipheriv(algorithm, this.kek, iv);
    cipher.setAutoPadding(false);

    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return encrypted;
  }

  /**
   * Calcula o MAC (CMAC) sobre os dados
   * Usa AES-CMAC ou TDES-CMAC dependendo do algoritmo
   */
  calculateMAC(data, algorithm, macLength) {
    // Usar CMAC (Cipher-based MAC)
    let cmacAlgorithm;

    if (algorithm === "A") {
      // AES-CMAC
      if (this.kek.length === 16) {
        cmacAlgorithm = "aes-128-cbc";
      } else if (this.kek.length === 24) {
        cmacAlgorithm = "aes-192-cbc";
      } else if (this.kek.length === 32) {
        cmacAlgorithm = "aes-256-cbc";
      }
    } else {
      // TDES-CMAC
      cmacAlgorithm = "des-ede3-cbc";
    }

    const blockSize = algorithm === "A" ? 16 : 8;

    // Implementação simplificada de CMAC usando CBC-MAC
    // Para produção, considere usar uma biblioteca especializada
    const key = algorithm === "A" ? this.kek : this.derive3DESKey(this.kek);
    const iv = Buffer.alloc(blockSize, 0);

    const cipher = crypto.createCipheriv(cmacAlgorithm, key, iv);
    cipher.setAutoPadding(false);

    // Adicionar padding CMAC se necessário
    const paddedData = this.addPadding(data, blockSize);

    let mac = cipher.update(paddedData);
    mac = Buffer.concat([mac, cipher.final()]);

    // Retornar apenas os últimos bytes do MAC
    return mac.slice(-macLength);
  }
}

module.exports = TR31Decoder;
