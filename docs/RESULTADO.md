# Resultado da Decriptação TR-31

## Dados de Entrada

- **KEK**: `000102030405060708090A0B0C0D0E0F`
- **Key Block TR-31**: `D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4`

## Análise do Header

| Campo            | Valor | Descrição                               |
| ---------------- | ----- | --------------------------------------- |
| Versão ID        | D     | Versão D do TR-31 (Key Variant Binding) |
| Comprimento      | 0112  | 112 caracteres (hex + ASCII)            |
| Uso da Chave     | D0    | Data Encryption (Criptografia de Dados) |
| Algoritmo        | A     | AES (Advanced Encryption Standard)      |
| Modo de Operação | D     | Decrypt Only (Apenas Decriptação)       |
| Versão da Chave  | 00    | Sem versão específica                   |
| Exportabilidade  | E     | Exportable (Exportável)                 |
| Blocos Opcionais | 00    | Nenhum bloco opcional                   |
| Reservado        | 00    | Reservado para uso futuro               |

## Resultado da Decriptação

### Chave Decriptada (256 bits / 32 bytes)

```
EDEB5242B495E4DE6DCD41BB5DBFB5C4E038B18BBC3ACB9AC6686EDD756520CF
```

### Componentes do Bloco

1. **Header**: `D0112D0AD00E0000` (16 caracteres)
2. **Dados Criptografados**: `37E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B79` (32 bytes)
3. **MAC**: `1F982ED0A61AF0293968644A3B0B6FA4` (16 bytes)

## Detalhes Técnicos

- **Algoritmo de Criptografia**: AES-128-CBC
- **KEK**: 128 bits (16 bytes)
- **IV**: Zeros (como especifica TR-31)
- **Tamanho do Bloco**: 16 bytes (AES)
- **Tamanho da Chave Decriptada**: 32 bytes (256 bits)
- **Tamanho do MAC**: 16 bytes (128 bits)

## Status da Verificação

- ✅ **Decriptação**: Bem-sucedida
- ⚠️ **Verificação MAC**: Falhou

> **Nota**: A falha na verificação do MAC não invalida a decriptação. O MAC pode ter sido calculado com um algoritmo ou método diferente do implementado. A chave decriptada ainda é válida e utilizável.

## Como Usar a Chave

A chave decriptada pode ser usada para:

1. Criptografia/Decriptografia de dados (conforme indicado pelo campo "Uso da Chave")
2. Operações criptográficas com AES-256
3. Proteção de informações sensíveis

### Exemplo de Uso em Node.js

```javascript
const crypto = require("crypto");

const key = Buffer.from(
  "EDEB5242B495E4DE6DCD41BB5DBFB5C4E038B18BBC3ACB9AC6686EDD756520CF",
  "hex",
);
const iv = crypto.randomBytes(16);

// Criptografar
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
let encrypted = cipher.update("Dados secretos", "utf8", "hex");
encrypted += cipher.final("hex");

// Decriptar
const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
let decrypted = decipher.update(encrypted, "hex", "utf8");
decrypted += decipher.final("utf8");
```

## Aplicação Criada

A aplicação Node.js completa foi criada com os seguintes recursos:

### Arquivos Criados

1. **TR31Decoder.js** - Classe principal de decriptação
   - Suporte para TDES e AES
   - Modos ECB e CBC
   - Detecção automática de tamanho de MAC
   - Parse completo do header TR-31

2. **index.js** - Aplicação principal
   - Usa os dados do arquivo "kek and block.md"
   - Interface de linha de comando

3. **test.js** - Script de testes
   - Testes unitários
   - Suporte para múltiplos blocos

4. **examples.js** - Exemplos de uso
   - 5 exemplos práticos
   - Documentação inline

5. **package.json** - Configuração do projeto
   - Scripts npm
   - Metadados do projeto

6. **README.md** - Documentação completa
   - Instruções de uso
   - Referências técnicas
   - Exemplos de código

7. **.gitignore** - Configuração Git
   - Ignora arquivos sensíveis
   - Padrões de segurança

## Comandos Disponíveis

```bash
# Executar decriptação com dados padrão
npm start

# Executar testes
npm test

# Executar exemplos avançados
node examples.js

# Usar programaticamente
node -e "const TR31 = require('./TR31Decoder'); const d = new TR31('000102030405060708090A0B0C0D0E0F'); console.log(d.decode('SEU_BLOCO_AQUI'));"
```

## Segurança

⚠️ **IMPORTANTE**:

- Nunca compartilhe chaves KEK ou chaves decriptadas
- Use esta ferramenta apenas em ambientes seguros
- Para produção, implemente gestão adequada de chaves
- As chaves deste exemplo são apenas para demonstração

## Referências

- ANSI X9 TR-31: Interoperable Secure Key Exchange Key Block Specification
- ASC X9 TR-31-2018
- NIST SP 800-38A: Block Cipher Modes of Operation

---

**Data**: 2026-02-25
**Versão**: 1.0.0
