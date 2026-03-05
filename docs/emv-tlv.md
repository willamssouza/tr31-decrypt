# EMV TLV - Guia rapido

## O que e EMV TLV

EMV TLV e o formato de dados usado em transacoes de cartao com chip.

- EMV: padrao de pagamentos com chip (Europay, Mastercard, Visa)
- TLV: estrutura binaria/hexadecimal em blocos:
  - Tag: identifica o campo
  - Length: tamanho do valor
  - Value: conteudo do campo

Esse formato permite mensagens extensiveis sem depender de layout fixo por posicao.

## Estrutura TLV

Cada campo segue o padrao:

```text
[TAG][LENGTH][VALUE]
```

Exemplo:

```text
9F0206000000010000
```

Leitura:

- Tag: `9F02` (Amount, Authorized)
- Length: `06` (6 bytes)
- Value: `000000010000`

## Como identificar os campos

1. Leia a Tag.
2. Leia o Length.
3. Leia `Length` bytes como Value.
4. Repita ate o fim do payload.
5. Se a Tag tiver estrutura propria (ex.: `57`), aplique a regra especifica dessa tag.

## Regras praticas de parsing

- Tag de 1 byte: quando o primeiro byte nao comeca com `9F`, `5F`, etc.
- Tag de 2 bytes (comum em EMV): exemplos `9F02`, `5F2A`, `9F36`.
- Length normalmente e 1 byte, mas o padrao TLV suporta formato longo.

## Tags EMV comuns

- `57`: Track 2 Equivalent Data
- `5A`: PAN (Primary Account Number)
- `5F24`: Application Expiration Date
- `5F2A`: Transaction Currency Code
- `82`: AIP (Application Interchange Profile)
- `84`: Dedicated File (DF) Name / AID
- `95`: TVR (Terminal Verification Results)
- `9A`: Transaction Date
- `9C`: Transaction Type
- `9F02`: Amount, Authorized
- `9F03`: Amount, Other
- `9F10`: Issuer Application Data
- `9F1A`: Terminal Country Code
- `9F26`: Application Cryptogram
- `9F27`: Cryptogram Information Data
- `9F36`: ATC (Application Transaction Counter)
- `9F37`: Unpredictable Number

## Exemplo real (inicio do payload)

Payload (trecho):

```text
57134761739001010119D22122011175898938900F820220008407A0000000031010...
```

Primeiros campos:

- `57 13 4761739001010119D22122011175898938900F`
  - Tag: `57`
  - Length: `13` (19 bytes)
  - Value: `4761739001010119D22122011175898938900F`

- `82 02 2000`
  - Tag: `82`
  - Length: `02`
  - Value: `2000`

- `84 07 A0000000031010`
  - Tag: `84`
  - Length: `07`
  - Value: `A0000000031010` (AID)

## Decodificacao da tag 57 (Track 2 Equivalent Data)

Formato geral da `57`:

```text
[PAN]D[YYMM][ServiceCode][DiscretionaryData][F opcional de padding]
```

Exemplo:

```text
4761739001010119D22122011175898938900F
```

Leitura:

- PAN: `4761739001010119`
- Separador: `D`
- Validade: `2212` (MM/AA = 12/22)
- Service Code: `201`
- Discretionary data: `1175898938900`
- `F`: padding

## Cuidados importantes

- Dados de cartao sao sensiveis: mascare PAN em logs (ex.: mostrar apenas BIN + ultimos 4).
- Nao persista track data em texto claro.
- Siga PCI DSS para armazenamento, transmissao e auditoria.
- Trate campos desconhecidos como TLV valido (nao descarte sem analise).

## Resumo

EMV TLV e um formato de pares Tag-Length-Value. Para identificar campos, percorra o payload lendo Tag, Length e Value em sequencia. Depois, aplique interpretacoes especificas para tags conhecidas (como `57`, `9F02`, `9A`, `5F2A`).
