const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const TR31Decoder = require("../tr31-decrypt");

// KEK (Key Encryption Key) - 32 bytes para AES-256
const kek = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";
const decoder = new TR31Decoder(kek);
const keyToProtect = "0123456789ABCDEFFEDCBA9876543210";

describe("TR-31 Encode/Decode - Testes Funcionais", () => {
  describe("Codificação e Decodificação Básica", () => {
    it("deve codificar e decodificar com opções padrão (AES-CBC)", () => {
      const keyBlock = decoder.encode(keyToProtect);
      const decoded = decoder.decode(keyBlock);
      const unpaddedKey = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        unpaddedKey.toString("hex").toUpperCase(),
        keyToProtect.toUpperCase(),
        "Chave recuperada deve ser igual à original",
      );
    });

    it("deve codificar e decodificar com TDES-CBC", () => {
      const keyBlock = decoder.encode(keyToProtect, {
        algorithm: "T",
        versionId: "D",
        keyUsage: "P0",
        modeOfUse: "B",
        macLength: 4,
      });

      const decoded = decoder.decode(keyBlock);
      const unpaddedKey = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        unpaddedKey.toString("hex").toUpperCase(),
        keyToProtect.toUpperCase(),
      );
    });

    it("deve codificar e decodificar com AES-ECB", () => {
      const keyBlock = decoder.encode(keyToProtect, {
        algorithm: "A",
        versionId: "B",
        keyUsage: "D0",
        modeOfUse: "E",
        macLength: 16,
        exportability: "N",
      });

      const decoded = decoder.decode(keyBlock);
      const unpaddedKey = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        unpaddedKey.toString("hex").toUpperCase(),
        keyToProtect.toUpperCase(),
      );
    });

    it("deve codificar e decodificar com TDES-ECB", () => {
      const keyBlock = decoder.encode(keyToProtect, {
        algorithm: "T",
        versionId: "B",
        keyUsage: "K0",
        modeOfUse: "E",
        macLength: 8,
      });

      const decoded = decoder.decode(keyBlock);
      const unpaddedKey = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        unpaddedKey.toString("hex").toUpperCase(),
        keyToProtect.toUpperCase(),
      );
    });
  });

  describe("Diferentes Tamanhos de Chaves", () => {
    it("deve processar chave de 8 bytes", () => {
      const key8bytes = "0123456789ABCDEF";
      const keyBlock = decoder.encode(key8bytes);
      const decoded = decoder.decode(keyBlock);
      const unpaddedKey = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        unpaddedKey.toString("hex").toUpperCase(),
        key8bytes.toUpperCase(),
      );
    });

    it("deve processar chave de 24 bytes", () => {
      const key24bytes = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF";
      const keyBlock = decoder.encode(key24bytes);
      const decoded = decoder.decode(keyBlock);
      const unpaddedKey = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        unpaddedKey.toString("hex").toUpperCase(),
        key24bytes.toUpperCase(),
      );
    });

    it("deve processar chave de 32 bytes", () => {
      const key32bytes =
        "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210";
      const keyBlock = decoder.encode(key32bytes);
      const decoded = decoder.decode(keyBlock);
      const unpaddedKey = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        unpaddedKey.toString("hex").toUpperCase(),
        key32bytes.toUpperCase(),
      );
    });
  });

  describe("Diferentes Tamanhos de MAC", () => {
    const macLengths = [4, 8, 16];

    macLengths.forEach((macLen) => {
      it(`deve processar com MAC de ${macLen} bytes`, () => {
        const keyBlock = decoder.encode(keyToProtect, { macLength: macLen });
        const decoded = decoder.decode(keyBlock);
        const unpaddedKey = decoder.removePadding(
          Buffer.from(decoded.decryptedData, "hex"),
        );

        assert.equal(
          unpaddedKey.toString("hex").toUpperCase(),
          keyToProtect.toUpperCase(),
        );
      });
    });
  });

  describe("Verificação de Header", () => {
    it("deve gerar header correto para AES-CBC", () => {
      const keyBlock = decoder.encode(keyToProtect, {
        algorithm: "A",
        versionId: "D",
        keyUsage: "D0",
        modeOfUse: "E",
        keyVersion: "00",
        exportability: "E",
      });

      const header = keyBlock.substring(0, 16);
      assert.equal(header[0], "D", "Version ID deve ser D");
      assert.equal(header.substring(5, 7), "D0", "Key Usage deve ser D0");
      assert.equal(header[7], "A", "Algorithm deve ser A");
      assert.equal(header[8], "E", "Mode of Use deve ser E");
    });

    it("deve gerar header correto para TDES-CBC", () => {
      const keyBlock = decoder.encode(keyToProtect, {
        algorithm: "T",
        versionId: "D",
        keyUsage: "P0",
        modeOfUse: "B",
      });

      const header = keyBlock.substring(0, 16);
      assert.equal(header[0], "D", "Version ID deve ser D");
      assert.equal(header.substring(5, 7), "P0", "Key Usage deve ser P0");
      assert.equal(header[7], "T", "Algorithm deve ser T");
      assert.equal(header[8], "B", "Mode of Use deve ser B");
    });
  });

  describe("Padding ISO 9797-1 Method 2", () => {
    it("deve adicionar padding corretamente", () => {
      const data = Buffer.from("0123456789ABCDEF", "hex");
      const padded = decoder.addPadding(data, 16);

      assert.equal(padded.length % 16, 0, "Dados devem estar alinhados");
      assert.equal(
        padded[data.length],
        0x80,
        "Primeiro byte de padding deve ser 0x80",
      );
    });

    it("deve remover padding corretamente", () => {
      const paddedData = Buffer.from(
        "0123456789ABCDEF80000000000000000000000000000000",
        "hex",
      );
      const unpadded = decoder.removePadding(paddedData);

      assert.equal(unpadded.length, 8, "Deve remover padding");
      assert.equal(unpadded.toString("hex").toUpperCase(), "0123456789ABCDEF");
    });

    it("deve lidar com dados sem padding", () => {
      const data = Buffer.from("0123456789ABCDEF", "hex");
      const result = decoder.removePadding(data);

      assert.equal(
        result.length,
        data.length,
        "Não deve remover nada se não houver padding válido",
      );
    });
  });
});
