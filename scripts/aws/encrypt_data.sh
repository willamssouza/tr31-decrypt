#!/bin/bash

PLAIN_TEXT=$(echo -n 'Test data 123456' | xxd -p)

aws payment-cryptography-data encrypt-data \
    --key-identifier arn:aws:payment-cryptography:us-east-1:839834288637:key/j2s3m26dsffgc3dq \
    --plain-text "$PLAIN_TEXT" \
    --encryption-attributes '{
        "Symmetric": {
            "Mode": "CBC",
            "PaddingType": "PKCS1"
        }
    }' \
    --region us-east-1