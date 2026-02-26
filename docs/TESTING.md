# Guia de Testes - TR-31 Decrypt

Este projeto usa o **test runner nativo do Node.js** (`node:test`) introduzido no Node.js 18+.

## 🚀 Quick Start

```bash
# Instalar dependências (nenhuma necessária!)
npm install

# Executar todos os testes
npm test

# Executar com output formatado
npm run test:spec
```

## 📋 Comandos Disponíveis

### Executar Todos os Testes
```bash
npm test
```
Executa os 64 testes em 3 suites:
- ✅ 23 testes funcionais (encode/decode)
- ✅ 27 testes de validação e erros
- ✅ 14 testes de performance

### Testes Individuais

```bash
# Apenas testes funcionais
npm run test:encode

# Apenas testes de validação
npm run test:errors

# Apenas testes de performance
npm run test:performance
```

### Formatos de Saída

```bash
# Reporter spec (mais legível e estruturado)
npm run test:spec

# Watch mode (reexecuta ao salvar arquivos)
npm run test:watch
```

## 📊 Estrutura dos Testes

### test-encode.test.js
Testa funcionalidades de codificação e decodificação:

```javascript
describe('TR-31 Encode/Decode - Testes Funcionais', () => {
  describe('Codificação e Decodificação Básica', () => {
    it('deve codificar e decodificar com opções padrão (AES-CBC)', () => {
      // Teste aqui
    });
  });
});
```

**Cobertura:**
- Codificação com AES-CBC, AES-ECB, TDES-CBC, TDES-ECB
- Diferentes tamanhos de chaves (8, 16, 24, 32 bytes)
- Diferentes tamanhos de MAC (4, 8, 16 bytes)
- Validação de headers TR-31
- Padding ISO 9797-1 Method 2

### test-errors.test.js
Testa validações e tratamento de erros:

```javascript
describe('TR-31 Validação e Tratamento de Erros', () => {
  it('deve lançar erro com KEK ausente (null)', () => {
    assert.throws(() => new TR31Decoder(null), /KEK.*obrigatória/i);
  });
});
```

**Cobertura:**
- Validação de KEK (null, vazio, tamanhos inválidos)
- Validação de parâmetros (MAC length, algoritmos)
- Validação de key blocks (formato, tamanho)
- Testes de padding
- Testes de consistência

### test-performance.test.js
Mede performance de operações:

```javascript
it('AES-CBC Encode deve executar 1000 iterações', () => {
  const result = benchmark('AES-CBC Encode', 1000, () => {
    decoder.encode(testKey, { algorithm: 'A', versionId: 'D' });
  });
  
  console.log(`⏱️  ${result.iterations} iterações em ${result.durationMs}ms`);
  console.log(`⚡ ${result.opsPerSec} ops/s`);
});
```

**Métricas:**
- Tempo total de execução
- Tempo médio por operação
- Operações por segundo
- Uso de memória (RSS, Heap, External)

## 🔍 Exemplo de Saída

### Reporter Padrão (TAP)
```
✔ deve codificar e decodificar com opções padrão (AES-CBC) (15.2ms)
✔ deve codificar e decodificar com TDES-CBC (12.5ms)
...
ℹ tests 64
ℹ pass 64
ℹ fail 0
```

### Reporter Spec
```
▶ TR-31 Encode/Decode - Testes Funcionais
  ▶ Codificação e Decodificação Básica
    ✔ deve codificar e decodificar com opções padrão (AES-CBC)
    ✔ deve codificar e decodificar com TDES-CBC
  ▶ Diferentes Tamanhos de Chaves
    ✔ deve processar chave de 8 bytes
    ✔ deve processar chave de 24 bytes
```

## 💡 Recursos do node:test

### Asserções Disponíveis
```javascript
const assert = require('node:assert/strict');

// Igualdade
assert.equal(actual, expected);
assert.strictEqual(actual, expected);

// Exceções
assert.throws(() => fn(), ErrorType);
assert.doesNotThrow(() => fn());

// Validações
assert.ok(value);
assert.match(string, regex);
```

### Hooks Disponíveis
```javascript
const { describe, it, before, after, beforeEach, afterEach } = require('node:test');

describe('Meus Testes', () => {
  before(() => { /* setup */ });
  after(() => { /* teardown */ });
  beforeEach(() => { /* antes de cada teste */ });
  afterEach(() => { /* após cada teste */ });
  
  it('deve fazer algo', () => { /* teste */ });
});
```

### Testes Assíncronos
```javascript
it('deve processar async', async () => {
  const result = await asyncOperation();
  assert.equal(result, expected);
});
```

### Skip e Only
```javascript
it.skip('teste ignorado', () => { /* não executa */ });
it.only('executa apenas este', () => { /* executa */ });
```

## 🎯 Benchmark Performance

Resultados médios (Node.js 20.x, Windows):

| Operação | Iterações | Ops/Segundo | Tempo Médio |
|----------|-----------|-------------|-------------|
| AES-CBC Encode | 1000 | ~17,000 | ~0.06 ms |
| AES-ECB Encode | 1000 | ~28,000 | ~0.04 ms |
| TDES-CBC Encode | 1000 | ~28,000 | ~0.04 ms |
| TDES-ECB Encode | 1000 | ~31,000 | ~0.03 ms |
| AES-CBC Decode | 1000 | ~12,000 | ~0.08 ms |
| Ciclo Completo | 500 | ~6,500 | ~0.15 ms |

## 📝 Escrevendo Novos Testes

### Template Básico
```javascript
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const TR31Decoder = require('../tr31-decrypt');

describe('Minha Nova Feature', () => {
  const kek = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";
  const decoder = new TR31Decoder(kek);
  
  it('deve fazer algo específico', () => {
    const result = decoder.encode('0123456789ABCDEF');
    assert.ok(result);
    assert.equal(typeof result, 'string');
  });
});
```

### Adicionar ao package.json
```json
{
  "scripts": {
    "test:minha-feature": "node --test tests/test-minha-feature.test.js"
  }
}
```

## 🐛 Depuração

### Executar teste específico
```bash
node --test tests/test-encode.test.js
```

### Com breakpoints
```bash
node inspect --test tests/test-encode.test.js
```

### Com logs detalhados
```bash
NODE_OPTIONS='--trace-warnings' npm test
```

## 📚 Referências

- [Node.js Test Runner](https://nodejs.org/api/test.html)
- [Node.js Assert](https://nodejs.org/api/assert.html)
- [TR-31 Standard](https://webstore.ansi.org/standards/ascx9/ansix9tr312018)

## ✅ Checklist de CI/CD

Para integração contínua, adicione ao seu `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18.x, 20.x, 21.x]
    
    steps:
      - uses: actions/checkout@v3
      - name: Use Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v3
        with:
          node-version: ${{ matrix.node-version }}
      - run: npm install
      - run: npm test
```

## 🎉 Conclusão

Todos os testes foram convertidos para usar o test runner nativo do Node.js, eliminando a necessidade de dependências externas como Jest, Mocha ou Chai!

**Vantagens:**
- ✅ Zero dependências
- ✅ Mais rápido que Jest/Mocha
- ✅ Sintaxe familiar (describe/it)
- ✅ Suporte nativo a async/await
- ✅ Watch mode integrado
- ✅ Reporters integrados
