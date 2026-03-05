#!/bin/bash
source ./wrapKeyWithRSAAES.sh

KEK_HEX="000102030405060708090A0B0C0D0E0F"
JSON_PARAMS="import-params.json"

# Remover arquivos temporários ao sair
trap "rm -f $JSON_PARAMS" EXIT

# Para importação TR-31
aws payment-cryptography get-parameters-for-import \
    --key-material-type KEY_CRYPTOGRAM \
    --wrapping-key-algorithm RSA_4096 \
    --region us-east-1 > "$JSON_PARAMS"

# Extrair certificado de empacotamento do JSON e salvar em um arquivo PEM
CERT_DATA=$(grep -o '"WrappingKeyCertificate"[[:space:]]*:[[:space:]]*"[^"]*"' "$JSON_PARAMS" | sed 's/.*"WrappingKeyCertificate"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
CERTIFICATE=$(echo "$CERT_DATA" | base64 --decode)

WRAPPED_KEY_CRYPTOGRAM=$(wrapKeyWithRSAAES "$KEK_HEX" "$CERTIFICATE")

# Validar se a chave wrapped é válida
if [[ -z "$WRAPPED_KEY_CRYPTOGRAM" ]]; then
    echo "Erro: Chave inválida" >&2
    exit 1
fi
echo "🔑 Wrapped Key Cryptogram: $WRAPPED_KEY_CRYPTOGRAM"

# Extrair Import Token do JSON
IMPORT_TOKEN=$(grep -o '"ImportToken"[[:space:]]*:[[:space:]]*"[^"]*"' "$JSON_PARAMS" | sed 's/.*"ImportToken"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

# Comando de importação da AWS
aws payment-cryptography import-key \
    --key-material KeyCryptogram="{
      ImportToken=$IMPORT_TOKEN,
      WrappedKeyCryptogram=$WRAPPED_KEY_CRYPTOGRAM,
      WrappingSpec=RSA_OAEP_SHA_256,
      Exportable=true,
      KeyAttributes={
        KeyAlgorithm=AES_128,
        KeyClass=SYMMETRIC_KEY,
        KeyUsage=TR31_K0_KEY_ENCRYPTION_KEY,
        KeyModesOfUse={
          Encrypt=true,
          Decrypt=true,
          Wrap=true,
          Unwrap=true
        }
      }
    }" \
    --key-check-value-algorithm ANSI_X9_24 \
    --enabled \
    --tags Key=Name,Value=ImportedKEK Key=Source,Value=TR31Decoder Key=Algorithm,Value=AES_256 \
    --region us-east-1

