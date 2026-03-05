# Comandos AWS Payment Cryptography

## 📋 Sumário

- [Configuração Inicial](#configuração-inicial)
- [Gerenciamento de Chaves](#gerenciamento-de-chaves)
- [Importação de Chaves](#importação-de-chaves)
- [Exportação de Chaves](#exportação-de-chaves)
- [Operações Criptográficas](#operações-criptográficas)
- [Scripts Node.js](#scripts-nodejs)

## 🔧 Configuração Inicial

### Instalar AWS CLI

```bash
# Windows (via winget)
winget install Amazon.AWSCLI

# Verificar instalação
aws --version
```

### Configurar Credenciais

```bash
# Configurar perfil padrão
aws configure

# Configurar perfil específico
aws configure --profile payment-crypto

# Variáveis exigidas:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region (us-east-1)
# - Default output format (json)
```

### Testar Conexão

```bash
# Listar chaves
aws payment-cryptography list-keys --region us-east-1

# Verificar identidade
aws sts get-caller-identity
```

## 🔑 Gerenciamento de Chaves

### Listar Chaves

```bash
# Listar todas as chaves
aws payment-cryptography list-keys --region us-east-1

# Listar com filtro de estado
aws payment-cryptography list-keys \
    --key-state CREATE_COMPLETE \
    --region us-east-1

# Formato tabela
aws payment-cryptography list-keys \
    --region us-east-1 \
    --output table
```

### Obter Detalhes de uma Chave

```bash
# Usando ARN
aws payment-cryptography get-key \
    --key-identifier arn:aws:payment-cryptography:us-east-1:839834288637:key/2dc6y23d26id2shc \
    --region us-east-1

# Usando Key ID (alias)
aws payment-cryptography get-key \
    --key-identifier alias/my-kek \
    --region us-east-1
```

### Criar Nova Chave

```bash
# Criar KEK (Key Encryption Key)
aws payment-cryptography create-key \
    --key-attributes '{
        "KeyAlgorithm": "TDES_2KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyUsage": "TR31_K0_KEY_ENCRYPTION_KEY",
        "KeyModesOfUse": {
            "Encrypt": true,
            "Decrypt": true,
            "Wrap": true,
            "Unwrap": true
        }
    }' \
    --exportable \
    --region us-east-1

# Criar PIN Encryption Key
aws payment-cryptography create-key \
    --key-attributes '{
        "KeyAlgorithm": "TDES_2KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyUsage": "TR31_P0_PIN_ENCRYPTION_KEY",
        "KeyModesOfUse": {
            "Encrypt": true,
            "Decrypt": true
        }
    }' \
    --region us-east-1
```

### Deletar Chave

```bash
# Deletar chave (com período de espera)
aws payment-cryptography delete-key \
    --key-identifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --delete-key-in-days 7 \
    --region us-east-1

# Deletar imediatamente (não recomendado)
aws payment-cryptography delete-key \
    --key-identifier arn:aws:payment-cryptography:us-east-1:839834288637:key/iyl5mbokuwpwpket \
    --delete-key-in-days 0 \
    --region us-east-1
```

## 📥 Importação de Chaves

### Obter Parâmetros para Importação

```bash
# Para importação TR-34
aws payment-cryptography get-parameters-for-import \
    --key-material-type TR34_KEY_BLOCK \
    --wrapping-key-algorithm RSA_2048 \
    --region us-east-1 > import-params.json

# Extrair certificado
cat import-params.json | jq -r '.WrappingKeyCertificate' > aws-wrapping-cert.pem
```

### Importar Chave TR-31

```bash
# Importar usando KEK existente
aws payment-cryptography import-key \
    --key-material '{
        "Tr31KeyBlock": {
            "WrappingKeyIdentifier": "arn:aws:payment-cryptography:us-east-1:839834288637:key/2dc6y23d26id2shc",
            "WrappedKeyBlock": "D0112D0AD00E000037E35A44A7A52B4C0E49AD9E39D0136625EF8BBCD8861AE97C1AB8E5862E8B791F982ED0A61AF0293968644A3B0B6FA4"
        }
    }' \
    --enabled \
    --region us-east-1
```

### Importar KEK usando TR-34

```bash
# Usar os parâmetros obtidos anteriormente
aws payment-cryptography import-key \
    --key-material '{
        "Tr34KeyBlock": {
            "CertificateAuthorityPublicKeyIdentifier": "'"$(cat import-params.json | jq -r .PublicKeyCertificate)"'",
            "ImportToken": "'"$(cat import-params.json | jq -r .ImportToken)"'",
            "WrappedKeyBlock": "BASE64_ENCRYPTED_KEY_HERE",
            "KeyBlockFormat": "X9_TR34_2012"
        }
    }' \
    --enabled \
    --region us-east-1
```

## 📤 Exportação de Chaves

### Exportar Chave (Wrapped)

```bash
# Exportar usando KEK
aws payment-cryptography export-key \
    --key-identifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --export-attributes KeyUsage=TR31_K0_KEY_ENCRYPTION_KEY \
    --key-material '{
        "Tr31KeyBlock": {
            "WrappingKeyIdentifier": "arn:aws:payment-cryptography:us-east-1:839834288637:key/2dc6y23d26id2shc"
        }
    }' \
    --region us-east-1
```

### Exportar para TR-31 Block

```bash
# Exportar no formato TR-31
aws payment-cryptography export-key \
    --key-identifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --key-material '{
        "Tr31KeyBlock": {
            "WrappingKeyIdentifier": "arn:aws:payment-cryptography:us-east-1:839834288637:key/2dc6y23d26id2shc"
        }
    }' \
    --region us-east-1 \
    --output json | jq -r '.WrappedKey.KeyMaterial'
```

## 🔐 Operações Criptográficas

### Encriptar Dados

```bash
# Encriptar dados com chave simétrica
aws payment-cryptography-data encrypt-data \
    --key-identifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --plain-text "$(echo -n 'Test data 123456' | base64)" \
    --encryption-attributes '{
        "Symmetric": {
            "Mode": "CBC",
            "PaddingType": "PKCS1"
        }
    }' \
    --region us-east-1
```

### Decriptar Dados

```bash
# Decriptar dados
aws payment-cryptography-data decrypt-data \
    --key-identifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --cipher-text "BASE64_ENCRYPTED_DATA" \
    --decryption-attributes '{
        "Symmetric": {
            "Mode": "ECB",
            "PaddingType": "PKCS1"
        }
    }' \
    --region us-east-1
```

### Gerar MAC

```bash
# Gerar MAC (Message Authentication Code)
aws payment-cryptography-data generate-mac \
    --key-identifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --message-data "$(echo -n 'Message to authenticate' | base64)" \
    --generation-attributes '{
        "Algorithm": "ISO9797_ALGORITHM3",
        "EmvMajorKeyDerivationMode": "EMV_OPTION_A",
        "PaddingType": "ISO_IEC_7816_4"
    }' \
    --region us-east-1
```

### Verificar MAC

```bash
# Verificar MAC
aws payment-cryptography-data verify-mac \
    --key-identifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --message-data "$(echo -n 'Message to authenticate' | base64)" \
    --mac "MAC_VALUE_HERE" \
    --verification-attributes '{
        "Algorithm": "ISO9797_ALGORITHM3",
        "EmvMajorKeyDerivationMode": "EMV_OPTION_A",
        "PaddingType": "ISO_IEC_7816_4"
    }' \
    --region us-east-1
```

## 📝 Tagging e Metadados

### Adicionar Tags

```bash
# Adicionar tags a uma chave
aws payment-cryptography tag-resource \
    --resource-arn arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --tags Key=Environment,Value=Production Key=Application,Value=TR31Decoder \
    --region us-east-1
```

### Listar Tags

```bash
# Listar tags de uma chave
aws payment-cryptography list-tags-for-resource \
    --resource-arn arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --region us-east-1
```

### Remover Tags

```bash
# Remover tags
aws payment-cryptography untag-resource \
    --resource-arn arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --tag-keys Environment Application \
    --region us-east-1
```

## 🔍 Aliases

### Criar Alias

```bash
# Criar alias para uma chave
aws payment-cryptography create-alias \
    --alias-name alias/my-production-kek \
    --key-id arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --region us-east-1
```

### Listar Aliases

```bash
# Listar todos os aliases
aws payment-cryptography list-aliases \
    --region us-east-1
```

### Atualizar Alias

```bash
# Atualizar alias para apontar para nova chave
aws payment-cryptography update-alias \
    --alias-name alias/my-production-kek \
    --key-id arn:aws:payment-cryptography:us-east-1:123456789012:key/xyz789 \
    --region us-east-1
```

### Deletar Alias

```bash
# Deletar alias
aws payment-cryptography delete-alias \
    --alias-name alias/my-production-kek \
    --region us-east-1
```

## 🎯 Scripts Node.js

### Instalação

```bash
# Instalar dependências
npm install @aws-sdk/client-payment-cryptography @aws-sdk/client-payment-cryptography-data
```

### Scripts Disponíveis

```bash
# 1. Importação completa (KEK + TR-31)
npm run aws:import

# 2. Importação simples (apenas TR-31 com KEK existente)
npm run aws:import-simple

# 3. Exemplo prático com sua KEK
npm run aws:example
```

### Uso Programático

```javascript
// Importar módulos
const {
  PaymentCryptographyClient,
  ImportKeyCommand,
} = require("@aws-sdk/client-payment-cryptography");

// Criar cliente
const client = new PaymentCryptographyClient({ region: "us-east-1" });

// Importar chave TR-31
const response = await client.send(
  new ImportKeyCommand({
    KeyMaterial: {
      Tr31KeyBlock: {
        WrappingKeyIdentifier: "arn:aws:payment-cryptography:...",
        WrappedKeyBlock: "D0112D0AD00E0000...",
      },
    },
    Enabled: true,
  }),
);

console.log("Chave importada:", response.Key.KeyArn);
```

## 🛠️ Troubleshooting

### Erro: AccessDeniedException

```bash
# Verificar permissões IAM
aws iam get-user
aws iam list-attached-user-policies --user-name YOUR_USERNAME

# Política necessária
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "payment-cryptography:*",
            "payment-cryptography-data:*"
        ],
        "Resource": "*"
    }]
}
```

### Erro: ValidationException

```bash
# Validar formato do bloco TR-31
node -e "
const tr31 = require('./tr31-decrypt');
const block = 'D0112D0AD00E0000...';
const kek = '000102030405060708090A0B0C0D0E0F';
console.log(tr31.decrypt(block, kek));
"
```

### Verificar Estado da Chave

```bash
# Chave deve estar em estado CREATE_COMPLETE
aws payment-cryptography get-key \
    --key-identifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
    --region us-east-1 \
    --query 'Key.KeyState'
```

## 📚 Recursos

- [AWS Payment Cryptography API Reference](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/)
- [AWS CLI Command Reference](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/payment-cryptography/index.html)
- [TR-31 Key Block Specification](https://www.x9.org/)
- [AWS SDK for JavaScript v3](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/payment-cryptography/)

## 🔐 Boas Práticas

1. **Nunca** exporte chaves em texto claro
2. Use **aliases** para facilitar rotação de chaves
3. Configure **CloudTrail** para auditoria
4. Implemente **tags** para organização
5. Use **KMS** para chaves de longa duração
6. Configure **alertas** para operações críticas
7. Implemente **rotação automática** de chaves
8. Use **IAM roles** em vez de usuários
9. Ative **MFA** para operações sensíveis
10. Documente **key check values** para validação
