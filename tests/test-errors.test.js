const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const TR31Decoder = require("../tr31-decrypt");

describe("TR-31 Validação e Tratamento de Erros", () => {
  describe("Validação do Construtor", () => {
    it("deve lançar erro com KEK ausente (null)", () => {
      assert.throws(
        () => new TR31Decoder(null),
        /KEK.*obrigatória/i,
        "Deve lançar erro quando KEK é null",
      );
    });

    it("deve lançar erro com KEK vazia", () => {
      assert.throws(
        () => new TR31Decoder(""),
        /KEK.*obrigatória/i,
        "Deve lançar erro quando KEK é string vazia",
      );
    });

    it("deve lançar erro com KEK de tamanho inválido (10 bytes)", () => {
      assert.throws(
        () => new TR31Decoder("0123456789ABCDEF0123"),
        /KEK deve ter 16, 24 ou 32 bytes/i,
        "Deve lançar erro quando KEK tem tamanho inválido",
      );
    });

    it("deve aceitar KEK válida de 16 bytes (128 bits)", () => {
      assert.doesNotThrow(
        () => new TR31Decoder("0123456789ABCDEF0123456789ABCDEF"),
        "Deve aceitar KEK de 16 bytes",
      );
    });

    it("deve aceitar KEK válida de 24 bytes (192 bits)", () => {
      assert.doesNotThrow(
        () =>
          new TR31Decoder("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
        "Deve aceitar KEK de 24 bytes",
      );
    });

    it("deve aceitar KEK válida de 32 bytes (256 bits)", () => {
      assert.doesNotThrow(
        () =>
          new TR31Decoder(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
          ),
        "Deve aceitar KEK de 32 bytes",
      );
    });
  });

  describe("Validação do Encode", () => {
    const validKek =
      "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";
    const decoder = new TR31Decoder(validKek);

    it("deve lançar erro com chave ausente (null)", () => {
      assert.throws(
        () => decoder.encode(null),
        Error,
        "Deve lançar erro quando chave é null",
      );
    });

    it("deve lançar erro com MAC length inválido (3 bytes)", () => {
      assert.throws(
        () => decoder.encode("0123456789ABCDEF", { macLength: 3 }),
        /MAC length deve ser 4, 8 ou 16/i,
        "Deve lançar erro com MAC length inválido",
      );
    });

    it("deve lançar erro com MAC length inválido (20 bytes)", () => {
      assert.throws(
        () => decoder.encode("0123456789ABCDEF", { macLength: 20 }),
        /MAC length deve ser 4, 8 ou 16/i,
        "Deve lançar erro com MAC length inválido",
      );
    });

    it("deve aceitar chave válida com opções padrão", () => {
      const result = decoder.encode("0123456789ABCDEF");
      assert.ok(result, "Deve retornar um resultado");
      assert.equal(typeof result, "string", "Resultado deve ser string");
      assert.ok(result.length > 0, "Resultado não deve estar vazio");
    });

    it("deve processar chave muito pequena (1 byte)", () => {
      assert.doesNotThrow(
        () => decoder.encode("AB"),
        "Deve processar chave de 1 byte",
      );
    });

    it("deve processar chave grande (64 bytes)", () => {
      const largeKey = "0123456789ABCDEF".repeat(8);
      assert.doesNotThrow(
        () => decoder.encode(largeKey),
        "Deve processar chave de 64 bytes",
      );
    });

    it("deve aceitar todas as MAC lengths válidas", () => {
      [4, 8, 16].forEach((macLen) => {
        assert.doesNotThrow(
          () => decoder.encode("0123456789ABCDEF", { macLength: macLen }),
          `Deve aceitar MAC length de ${macLen} bytes`,
        );
      });
    });
  });

  describe("Validação do Decode", () => {
    const validKek =
      "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";
    const decoder = new TR31Decoder(validKek);

    it("deve lançar erro com key block ausente (null)", () => {
      assert.throws(
        () => decoder.decode(null),
        /KeyBlock é obrigatório/i,
        "Deve lançar erro quando key block é null",
      );
    });

    it("deve lançar erro com key block vazio", () => {
      assert.throws(
        () => decoder.decode(""),
        /KeyBlock é obrigatório/i,
        "Deve lançar erro quando key block é vazio",
      );
    });

    it("deve lançar erro com key block muito curto", () => {
      assert.throws(
        () => decoder.decode("0123456789"),
        Error,
        "Deve lançar erro com key block muito curto",
      );
    });

    it("deve lançar erro com caracteres hexadecimais inválidos", () => {
      assert.throws(
        () => decoder.decode("D0112D0AD00E0000GGGGGGGG"),
        Error,
        "Deve lançar erro com caracteres inválidos",
      );
    });

    it("deve decodificar key block válido", () => {
      const keyBlock = decoder.encode("0123456789ABCDEF");
      const result = decoder.decode(keyBlock);

      assert.ok(result, "Deve retornar um resultado");
      assert.ok(result.decryptedData, "Deve ter dados decriptados");
      assert.ok(result.header, "Deve ter header");
      assert.ok(result.mac, "Deve ter MAC");
    });
  });

  describe("Testes de Padding", () => {
    const validKek =
      "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";
    const decoder = new TR31Decoder(validKek);

    it("deve adicionar padding a dados vazios", () => {
      const empty = Buffer.from("");
      const padded = decoder.addPadding(empty, 16);

      assert.equal(
        padded.length,
        16,
        "Dados vazios com padding devem ter 16 bytes",
      );
      assert.equal(padded[0], 0x80, "Primeiro byte deve ser 0x80");
    });

    it("deve remover padding válido", () => {
      const data = Buffer.from(
        "0123456789ABCDEF80000000000000000000000000000000",
        "hex",
      );
      const unpadded = decoder.removePadding(data);

      assert.equal(unpadded.length, 8, "Deve remover padding corretamente");
      assert.equal(unpadded.toString("hex").toUpperCase(), "0123456789ABCDEF");
    });

    it("deve retornar dados originais se não houver padding", () => {
      const data = Buffer.from("0123456789ABCDEF", "hex");
      const result = decoder.removePadding(data);

      assert.equal(
        result.length,
        data.length,
        "Não deve modificar dados sem padding",
      );
    });

    it("deve adicionar padding com tamanho de bloco 8", () => {
      const data = Buffer.from("0123456789ABCDEF", "hex");
      const padded = decoder.addPadding(data, 8);

      assert.equal(
        padded.length % 8,
        0,
        "Dados com padding devem ser múltiplos de 8",
      );
      assert.equal(padded[data.length], 0x80, "Deve adicionar 0x80");
    });

    it("deve adicionar padding com tamanho de bloco 16", () => {
      const data = Buffer.from("0123456789ABCDEF", "hex");
      const padded = decoder.addPadding(data, 16);

      assert.equal(
        padded.length % 16,
        0,
        "Dados com padding devem ser múltiplos de 16",
      );
      assert.equal(padded[data.length], 0x80, "Deve adicionar 0x80");
    });
  });

  describe("Testes de Consistência (Encode -> Decode)", () => {
    const validKek =
      "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";
    const decoder = new TR31Decoder(validKek);

    const combinations = [
      { algorithm: "A", versionId: "D", name: "AES-CBC" },
      { algorithm: "A", versionId: "B", name: "AES-ECB" },
      { algorithm: "T", versionId: "D", name: "TDES-CBC" },
      { algorithm: "T", versionId: "B", name: "TDES-ECB" },
    ];

    combinations.forEach((combo) => {
      it(`deve manter consistência com ${combo.name}`, () => {
        const originalKey = "FEDCBA9876543210";
        const encoded = decoder.encode(originalKey, combo);
        const decoded = decoder.decode(encoded);
        const recovered = decoder.removePadding(
          Buffer.from(decoded.decryptedData, "hex"),
        );

        assert.equal(
          recovered.toString("hex").toUpperCase(),
          originalKey.toUpperCase(),
          `Chave recuperada deve ser igual à original para ${combo.name}`,
        );
      });
    });
  });

  describe("Testes de Diferentes Configurações", () => {
    const validKek =
      "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";
    const decoder = new TR31Decoder(validKek);
    const testKey = "0123456789ABCDEF";

    it("deve processar com key usage P0 (PIN Encryption)", () => {
      const keyBlock = decoder.encode(testKey, { keyUsage: "P0" });
      const decoded = decoder.decode(keyBlock);
      const recovered = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        recovered.toString("hex").toUpperCase(),
        testKey.toUpperCase(),
      );
    });

    it("deve processar com key usage K0 (Key Encryption Key)", () => {
      const keyBlock = decoder.encode(testKey, { keyUsage: "K0" });
      const decoded = decoder.decode(keyBlock);
      const recovered = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        recovered.toString("hex").toUpperCase(),
        testKey.toUpperCase(),
      );
    });

    it("deve processar com exportability N (Non-exportable)", () => {
      const keyBlock = decoder.encode(testKey, { exportability: "N" });
      const decoded = decoder.decode(keyBlock);
      const recovered = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        recovered.toString("hex").toUpperCase(),
        testKey.toUpperCase(),
      );
    });

    it("deve processar com mode of use B (Both)", () => {
      const keyBlock = decoder.encode(testKey, { modeOfUse: "B" });
      const decoded = decoder.decode(keyBlock);
      const recovered = decoder.removePadding(
        Buffer.from(decoded.decryptedData, "hex"),
      );

      assert.equal(
        recovered.toString("hex").toUpperCase(),
        testKey.toUpperCase(),
      );
    });
  });
});
