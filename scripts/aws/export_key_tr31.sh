#!/bin/bash

# ARN da KEK criada
KEK_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/laxd576r5b55k5vs"

# Exportar a KEK em formato TR-31
aws payment-cryptography export-key \
    --key-material='{
        "Tr31KeyBlock": { 
            "WrappingKeyIdentifier": "'$KEK_ARN'" 
        }
    }' \
    --export-key-identifier $KEK_ARN \
    --region us-east-1