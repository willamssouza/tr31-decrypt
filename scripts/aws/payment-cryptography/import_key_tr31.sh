#!/bin/bash

KEK_CARD_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/5v5rarn37wvpnky7"
KEK_PIN_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/44oefwxdeio4a4dg"
TR31_KEY_BLOCK="D0112D0AD00E00009ef4ff063d9757987d1768a1e317a6530de7d8ac81972c19a3659afb28e8d35f48aaa5b0f124e73893163e9a020ae5f3"

aws payment-cryptography import-key \
    --key-material '{
        "Tr31KeyBlock": {
            "WrappingKeyIdentifier": "'$KEK_CARD_ARN'",
            "WrappedKeyBlock": "'$TR31_KEY_BLOCK'"
        }
    }' \
    --enabled \
    --region us-east-1