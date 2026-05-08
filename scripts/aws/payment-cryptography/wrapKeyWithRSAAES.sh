#!/bin/bash

# Função para wrap de chave usando RSA-OAEP SHA-256
# Parâmetros:
#   $1 - KEK em hexadecimal
#   $2 - Certificado PEM (string ou arquivo)
wrapKeyWithRSAAES() {
    local key_hex="$1"
    local certificate="$2"
    
    echo "🔐 Iniciando wrap da chave com RSA-OAEP SHA-256..." >&2
    
    # Criar arquivo temporário para a chave
    local key_file=$(mktemp)
    local cert_file=$(mktemp)
    local encrypted_file=$(mktemp)

    # Limpar arquivos temporários ao sair
    trap "rm -f $key_file $cert_file $encrypted_file" EXIT
    
    # Converter HEX para binário
    echo "$key_hex" | xxd -r -p > "$key_file"
    echo "✓ Chave convertida de HEX para binário" >&2
    echo "  - Tamanho da chave: $(stat -c%s "$key_file") bytes" >&2
    echo "  - Conteúdo (HEX): $(xxd -p -c 256 "$key_file" | tr -d '\n' | tr '[:lower:]' '[:upper:]')" >&2
    
    # Verificar se o certificado é um arquivo ou string
    if [[ -f "$certificate" ]]; then
        cp "$certificate" "$cert_file"
        echo "✓ Usando certificado do arquivo" >&2
    elif [[ "$certificate" == *"-----BEGIN CERTIFICATE-----"* ]]; then
        echo "$certificate" > "$cert_file"
        echo "✓ Usando certificado da string PEM" >&2
    else
        # Assumir que é Base64 puro e precisa decodificar
        echo "$certificate" | base64 -d > "$cert_file"
        echo "✓ Certificado decodificado de Base64" >&2
    fi
    
    # Extrair chave pública do certificado
    local pubkey_file=$(mktemp)
    openssl x509 -in "$cert_file" -pubkey -noout > "$pubkey_file" || {
        echo "❌ Erro ao extrair chave pública do certificado" >&2
        return 1
    }

    echo "✓ Chave pública extraída do certificado" >&2
    
    # Encriptar usando RSA-OAEP com SHA-256
    openssl pkeyutl \
        -encrypt \
        -pubin \
        -inkey "$pubkey_file" \
        -in "$key_file" \
        -out "$encrypted_file" \
        -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha256 \
        -pkeyopt rsa_mgf1_md:sha256
    
    if [[ $? -eq 0 ]]; then
        echo "✅ Chave encriptada com sucesso" >&2
        # Converter para HEX maiúsculo
        xxd -p -c 256 "$encrypted_file" | tr -d '\n' | tr '[:lower:]' '[:upper:]'
    else
        echo "❌ Erro ao encriptar chave" >&2
        return 1
    fi
    
    # Limpar arquivos temporários
    rm -f "$pubkey_file" "$key_file" "$cert_file" "$encrypted_file"
}