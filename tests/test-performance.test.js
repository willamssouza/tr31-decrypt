const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const TR31Decoder = require("../tr31-decrypt");

const kek = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";
const decoder = new TR31Decoder(kek);
const testKey = "0123456789ABCDEFFEDCBA9876543210";

function benchmark(name, iterations, fn) {
  const start = process.hrtime.bigint();

  for (let i = 0; i < iterations; i++) {
    fn();
  }

  const end = process.hrtime.bigint();
  const durationMs = Number(end - start) / 1_000_000;
  const opsPerSec = (iterations / durationMs) * 1000;

  return {
    iterations,
    durationMs: durationMs.toFixed(2),
    avgMs: (durationMs / iterations).toFixed(3),
    opsPerSec: opsPerSec.toFixed(0),
  };
}

describe("TR-31 Performance e Benchmarks", () => {
  describe("Performance de Codificação", () => {
    it("AES-CBC Encode deve executar 1000 iterações", () => {
      const result = benchmark("AES-CBC Encode", 1000, () => {
        decoder.encode(testKey, { algorithm: "A", versionId: "D" });
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });

    it("AES-ECB Encode deve executar 1000 iterações", () => {
      const result = benchmark("AES-ECB Encode", 1000, () => {
        decoder.encode(testKey, { algorithm: "A", versionId: "B" });
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });

    it("TDES-CBC Encode deve executar 1000 iterações", () => {
      const result = benchmark("TDES-CBC Encode", 1000, () => {
        decoder.encode(testKey, { algorithm: "T", versionId: "D" });
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });

    it("TDES-ECB Encode deve executar 1000 iterações", () => {
      const result = benchmark("TDES-ECB Encode", 1000, () => {
        decoder.encode(testKey, { algorithm: "T", versionId: "B" });
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });
  });

  describe("Performance de Decodificação", () => {
    const keyBlockAES_CBC = decoder.encode(testKey, {
      algorithm: "A",
      versionId: "D",
    });
    const keyBlockAES_ECB = decoder.encode(testKey, {
      algorithm: "A",
      versionId: "B",
    });
    const keyBlockTDES_CBC = decoder.encode(testKey, {
      algorithm: "T",
      versionId: "D",
    });
    const keyBlockTDES_ECB = decoder.encode(testKey, {
      algorithm: "T",
      versionId: "B",
    });

    it("AES-CBC Decode deve executar 1000 iterações", () => {
      const result = benchmark("AES-CBC Decode", 1000, () => {
        decoder.decode(keyBlockAES_CBC);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });

    it("AES-ECB Decode deve executar 1000 iterações", () => {
      const result = benchmark("AES-ECB Decode", 1000, () => {
        decoder.decode(keyBlockAES_ECB);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });

    it("TDES-CBC Decode deve executar 1000 iterações", () => {
      const result = benchmark("TDES-CBC Decode", 1000, () => {
        decoder.decode(keyBlockTDES_CBC);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });

    it("TDES-ECB Decode deve executar 1000 iterações", () => {
      const result = benchmark("TDES-ECB Decode", 1000, () => {
        decoder.decode(keyBlockTDES_ECB);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });
  });

  describe("Performance de Ciclo Completo", () => {
    it("AES-CBC ciclo completo (encode + decode) deve executar 500 iterações", () => {
      const result = benchmark("AES-CBC Full Cycle", 500, () => {
        const encoded = decoder.encode(testKey, {
          algorithm: "A",
          versionId: "D",
        });
        decoder.decode(encoded);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });

    it("TDES-CBC ciclo completo (encode + decode) deve executar 500 iterações", () => {
      const result = benchmark("TDES-CBC Full Cycle", 500, () => {
        const encoded = decoder.encode(testKey, {
          algorithm: "T",
          versionId: "D",
        });
        decoder.decode(encoded);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s (${result.avgMs}ms/op)`);

      assert.ok(
        parseFloat(result.durationMs) < 10000,
        "Deve completar em menos de 10 segundos",
      );
    });
  });

  describe("Performance com Diferentes Tamanhos de Chave", () => {
    const key8 = "0123456789ABCDEF";
    const key16 = "0123456789ABCDEFFEDCBA9876543210";
    const key32 =
      "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210";
    const key64 = key32 + key32;

    it("Encode chave 8 bytes deve executar 1000 iterações", () => {
      const result = benchmark("Encode 8 bytes", 1000, () => {
        decoder.encode(key8);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s`);
    });

    it("Encode chave 16 bytes deve executar 1000 iterações", () => {
      const result = benchmark("Encode 16 bytes", 1000, () => {
        decoder.encode(key16);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s`);
    });

    it("Encode chave 32 bytes deve executar 1000 iterações", () => {
      const result = benchmark("Encode 32 bytes", 1000, () => {
        decoder.encode(key32);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s`);
    });

    it("Encode chave 64 bytes deve executar 1000 iterações", () => {
      const result = benchmark("Encode 64 bytes", 1000, () => {
        decoder.encode(key64);
      });

      console.log(
        `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
      );
      console.log(`  ⚡ ${result.opsPerSec} ops/s`);
    });
  });

  describe("Performance com Diferentes Tamanhos de MAC", () => {
    [4, 8, 16].forEach((macLen) => {
      it(`Encode com MAC ${macLen} bytes deve executar 1000 iterações`, () => {
        const result = benchmark(`MAC ${macLen} bytes`, 1000, () => {
          decoder.encode(testKey, { macLength: macLen });
        });

        console.log(
          `  ⏱️  ${result.iterations} iterações em ${result.durationMs}ms`,
        );
        console.log(`  ⚡ ${result.opsPerSec} ops/s`);
      });
    });
  });

  describe("Análise de Memória", () => {
    it("deve reportar uso de memória atual", () => {
      const used = process.memoryUsage();

      console.log("\n  💾 Uso de Memória:");
      console.log(`    RSS: ${(used.rss / 1024 / 1024).toFixed(2)} MB`);
      console.log(
        `    Heap Total: ${(used.heapTotal / 1024 / 1024).toFixed(2)} MB`,
      );
      console.log(
        `    Heap Usado: ${(used.heapUsed / 1024 / 1024).toFixed(2)} MB`,
      );
      console.log(
        `    External: ${(used.external / 1024 / 1024).toFixed(2)} MB`,
      );

      assert.ok(used.heapUsed > 0, "Heap deve estar em uso");
      assert.ok(
        used.heapUsed < 500 * 1024 * 1024,
        "Heap usado deve ser menor que 500MB",
      );
    });
  });
});
