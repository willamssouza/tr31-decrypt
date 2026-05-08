#!/bin/bash

KEY_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/a6o2bpzd6zfolfxx"
PLAIN_TEXT=$(echo -n 'Test data 123456' | xxd -p)

aws payment-cryptography-data encrypt-data \
    --key-identifier $KEY_ARN \
    --plain-text "$PLAIN_TEXT" \
    --encryption-attributes '{
        "Symmetric": {
            "Mode": "CBC"
        }
    }' \
    --region us-east-1