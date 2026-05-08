#!/bin/bash

REGION=${1:-us-east-1}

echo "Buscando todas as chaves na região: $REGION"

# Lista todos os ARNs de chaves ativas
KEY_ARNS=$(aws payment-cryptography list-keys \
    --region "$REGION" \
    --query 'Keys[*].KeyArn' \
    --output text)

if [ -z "$KEY_ARNS" ]; then
    echo "Nenhuma chave encontrada."
    exit 0
fi

echo "Chaves encontradas:"
echo "$KEY_ARNS" | tr '\t' '\n'
echo ""

read -p "Tem certeza que deseja deletar TODAS as chaves acima? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Operação cancelada."
    exit 0
fi

# Deleta cada chave
for KEY_ARN in $KEY_ARNS; do
    echo "Deletando: $KEY_ARN"
    aws payment-cryptography delete-key \
        --key-identifier "$KEY_ARN" \
        --region "$REGION" \
        && echo "  ✓ Deletada com sucesso" \
        || echo "  ✗ Falha ao deletar"
done

echo ""
echo "Processo concluído."