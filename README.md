# TR-31 Encrypt/Decrypt - Node.js

Aplicação Node.js para codificação e decriptografia de blocos de chave TR-31 (ANSI X9 TR-31).

## 📋 Sobre

O TR-31 é um padrão para formato de bloco de chave usado em sistemas de pagamento e criptografia. Esta biblioteca implementa tanto a **codificação** quanto a **decodificação** de blocos TR-31 usando KEK (Key Encryption Key).

## 🚀 Instalação

```bash
# Clonar o repositório
git clone https://github.com/willamssouza/tr31-decrypt.git
cd tr31-decrypt

# Não há dependências externas - usa apenas módulos nativos do Node.js
npm install
```

## 💻 Uso

### Decodificação (Descriptografia)

#### Uso Básico

```bash
npm start
```

Isso executará o decoder com os valores padrão definidos em `index.js`:

- **KEK**: `000102030405060708090A0B0C0D0E0F`
- **Key Block**: `D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4`

#### Uso Programático

```javascript
const TR31Decoder = require("./tr31-decoder");

// Sua KEK (Key Encryption Key) em hexadecimal
const KEK = "000102030405060708090A0B0C0D0E0F";

// Seu bloco TR-31 em hexadecimal
const KEY_BLOCK =
  "D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4";

try {
  // Criar instância do decoder
  const decoder = new TR31Decoder(KEK);

  // Decodificar o bloco
  const result = decoder.decode(KEY_BLOCK);

  console.log("Header:", result.header);
  console.log("Chave decriptada:", result.decryptedData);
  console.log("MAC:", result.mac);

  // Remover padding da chave se necessário
  const unpaddedKey = decoder.removePadding(
    Buffer.from(result.decryptedData, "hex"),
  );
  console.log("Chave sem padding:", unpaddedKey.toString("hex"));
} catch (error) {
  console.error("Erro:", error.message);
}
```

### Codificação (Criptografia)

#### Uso Programático

```javascript
const TR31Decoder = require("./tr31-decoder");

// Sua KEK (Key Encryption Key) em hexadecimal
const KEK = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";

// Chave a ser protegida em hexadecimal
const keyToProtect = "0123456789ABCDEFFEDCBA9876543210";

try {
  // Criar instância do encoder/decoder
  const encoder = new TR31Decoder(KEK);

  // Codificar com opções padrão (AES-CBC, MAC de 8 bytes)
  const keyBlock = encoder.encode(keyToProtect);
  console.log("Bloco TR-31 criado:", keyBlock);

  // Codificar com opções personalizadas
  const keyBlockCustom = encoder.encode(keyToProtect, {
    versionId: "D", // 'D' para CBC, 'B' para ECB
    keyUsage: "P0", // PIN Encryption
    algorithm: "A", // 'A' para AES, 'T' para TDES
    modeOfUse: "B", // Both encrypt and decrypt
    keyVersion: "00", // Versão da chave
    exportability: "E", // 'E' exportável, 'N' não exportável
    macLength: 8, // 4, 8 ou 16 bytes
  });

  console.log("Bloco TR-31 customizado:", keyBlockCustom);
} catch (error) {
  console.error("Erro:", error.message);
}
```

#### Teste de Codificação

Execute o teste completo de codificação e decodificação:

```bash
node test-encode.js
```

## 🔐 Formato TR-31

### Estrutura do Header (16 bytes)

| Posição | Tamanho | Campo           | Descrição                         |
| ------- | ------- | --------------- | --------------------------------- |
| 0       | 1       | Version ID      | Identificador da versão (ex: 'D') |
| 1-4     | 4       | Length          | Comprimento total do bloco        |
| 5-6     | 2       | Key Usage       | Uso da chave                      |
| 7       | 1       | Algorithm       | Algoritmo (T=TDES, A=AES)         |
| 8       | 1       | Mode of Use     | Modo de operação                  |
| 9-10    | 2       | Key Version     | Versão da chave                   |
| 11      | 1       | Exportability   | Exportabilidade                   |
| 12-13   | 2       | Optional Blocks | Número de blocos opcionais        |
| 14-15   | 2       | Reserved        | Reservado                         |

### Key Usage Codes

- **B0**: BDK (Base Derivation Key)
- **D0**: Data Encryption
- **I0**: IV (Initialization Vector)
- **K0**: Key Encryption Key
- **P0**: PIN Encryption
- **S0**: Signature Key
- **V0**: PIN Verification

### Algorithm Codes

- **T**: TDES (Triple DES)
- **A**: AES

### Mode of Use Codes

- **B**: Both Encrypt & Decrypt
- **D**: Decrypt Only
- **E**: Encrypt Only
- **S**: Signature Only
- **V**: Verification Only

## 🔐 Padding

A biblioteca utiliza **ISO 9797-1 Method 2** (também conhecido como padding 80 00 00):

- **Adição de Padding**: Adiciona `0x80` seguido de `0x00` até completar o tamanho do bloco
- **Remoção de Padding**: Remove automaticamente o padding após descriptografia

Exemplo:

```
Dados originais:    0123456789ABCDEFFEDCBA9876543210 (16 bytes)
Com padding:        0123456789ABCDEFFEDCBA9876543210800000000000000000000000000000 (32 bytes)
```

Para remover o padding após decodificar:

```javascript
const result = decoder.decode(keyBlock);
const decryptedBuffer = Buffer.from(result.decryptedData, "hex");
const unpaddedKey = decoder.removePadding(decryptedBuffer);
console.log("Chave original:", unpaddedKey.toString("hex"));
```

## 🛠️ Funcionalidades

### Decodificação (Descriptografia)

- ✅ Decriptografia de blocos TR-31
- ✅ Suporte para TDES (Triple DES) em modo ECB e CBC
- ✅ Suporte para AES-128, AES-192 e AES-256 em modo ECB e CBC
- ✅ Parse completo do header TR-31
- ✅ Detecção automática do tamanho do MAC (4, 6, 8 ou 16 bytes)
- ✅ Remoção de padding ISO 9797-1 Method 2
- ✅ Suporte para KEK de 128, 192 e 256 bits

### Codificação (Criptografia)

- ✅ Criação de blocos TR-31
- ✅ Suporte para TDES (Triple DES) em modo ECB e CBC
- ✅ Suporte para AES-128, AES-192 e AES-256 em modo ECB e CBC
- ✅ Adição automática de padding ISO 9797-1 Method 2
- ✅ Cálculo de MAC (CMAC) configurável (4, 8 ou 16 bytes)
- ✅ Configuração flexível de todos os campos do header
- ✅ Validação completa de entrada e parâmetros

## 📊 Exemplo Completo (Codificar e Decodificar)

```javascript
const TR31Decoder = require("./tr31-decoder");

// KEK em hexadecimal (32 bytes para AES-256)
const KEK = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE9";

// Chave a ser protegida (16 bytes)
const originalKey = "0123456789ABCDEFFEDCBA9876543210";

// Criar instância
const tr31 = new TR31Decoder(KEK);

// 1. CODIFICAR - Criar bloco TR-31
console.log("=== CODIFICAÇÃO ===");
const keyBlock = tr31.encode(originalKey, {
  versionId: "D", // CBC mode
  keyUsage: "D0", // Data Encryption
  algorithm: "A", // AES
  modeOfUse: "E", // Encrypt only
  macLength: 8, // 8 bytes MAC
});
console.log("Bloco TR-31:", keyBlock);

// 2. DECODIFICAR - Recuperar a chave
console.log("\n=== DECODIFICAÇÃO ===");
const result = tr31.decode(keyBlock);
console.log("Chave com padding:", result.decryptedData);

// 3. REMOVER PADDING - Obter chave original
const decryptedBuffer = Buffer.from(result.decryptedData, "hex");
const recoveredKey = tr31.removePadding(decryptedBuffer);
console.log("Chave recuperada:", recoveredKey.toString("hex").toUpperCase());

// 4. VERIFICAÇÃO
const match =
  recoveredKey.toString("hex").toUpperCase() === originalKey.toUpperCase();
console.log("\n✓ Verificação:", match ? "SUCESSO!" : "FALHOU!");
```

## 📊 Exemplo de Saída (Decodificação)

```
===========================================
    TR-31 KEY BLOCK DECODER
===========================================

KEK (Key Encryption Key): 000102030405060708090A0B0C0D0E0F
Key Block: D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4

=== INFORMAÇÕES DO HEADER ===
Versão ID: D
Comprimento total: 0112
Uso da chave: D0
Algoritmo: A
Modo de operação: D
Versão da chave: 00
Exportabilidade: E
Blocos opcionais: 00
Reservado: 00

=== DADOS CRIPTOGRAFADOS ===
Tamanho: 40 bytes
Hex: 37E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF029

MAC: 3968644A3B0B6FA4

=== DADOS DECRIPTADOS ===
Tamanho: 40 bytes
Hex: [dados decriptados]
ASCII: [representação ASCII]

=== VERIFICAÇÃO DO MAC ===
MAC válido: SIM/NÃO
```

## 🔧 Teste com Seus Próprios Dados

Para testar com seus próprios dados, use o arquivo `test.js`:

```javascript
const TR31Decoder = require("./TR31Decoder");

// Substitua com suas próprias chaves
const YOUR_KEK = "SUA_KEK_AQUI";
const YOUR_KEY_BLOCK = "SEU_BLOCO_TR31_AQUI";

const decoder = new TR31Decoder(YOUR_KEK);
const result = decoder.decode(YOUR_KEY_BLOCK);

console.log(result);
```

Execute:

```bash
npm test
```

## ⚠️ Requisitos

- Node.js >= 14.0.0
- Nenhuma dependência externa

## 📚 Referências

- ANSI X9 TR-31: Interoperable Secure Key Exchange Key Block Specification
- ASC X9 TR-31-2018

## 🔒 Segurança

**IMPORTANTE**: Este código é para fins educacionais e de teste. Para uso em produção:

- Nunca armazene chaves em código fonte
- Use variáveis de ambiente ou sistemas de gerenciamento de chaves
- Implemente logs de auditoria adequados
- Siga as melhores práticas de segurança da sua organização

## 📝 Licença

MIT

## 👨‍💻 Desenvolvimento

Para contribuir ou modificar:

1. A classe principal está em `tr31-decoder.js`
2. Principais métodos:
   - `encode(keyData, options)` - Codifica/criptografa uma chave em bloco TR-31
   - `decode(keyBlock)` - Decodifica/descriptografa um bloco TR-31
   - `addPadding(data, blockSize)` - Adiciona padding ISO 9797-1 Method 2
   - `removePadding(data)` - Remove padding ISO 9797-1 Method 2
3. Modifique os valores de teste em `index.js` ou `test-encode.js`
4. Execute `npm start` para teste de decodificação
5. Execute `node test-encode.js` para teste de codificação

## 🐛 Problemas Conhecidos

### Decodificação

- A verificação de MAC pode variar dependendo do método de cálculo usado pelo emissor do bloco
- Alguns blocos TR-31 podem usar variações proprietárias do padrão

### Codificação

- O cálculo de MAC usa uma implementação simplificada de CMAC baseada em CBC-MAC
- Para uso em produção, considere usar uma biblioteca especializada em CMAC

## 📞 Suporte

### Para problemas de decodificação:

- A KEK está correta?
- O Key Block está em formato hexadecimal válido?
- O formato do bloco está de acordo com o padrão TR-31?

### Para problemas de codificação:

- A chave a ser protegida está em formato hexadecimal?
- As opções fornecidas são válidas (keyUsage, algorithm, etc.)?
- O tamanho da KEK é suportado (16, 24 ou 32 bytes)?
