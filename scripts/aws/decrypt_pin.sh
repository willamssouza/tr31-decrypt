#!/bin/bash

KEY_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/2z4vw3xz4xsfsjsf"
SALT="kQ66ffUuY1XjAsvX02M0Cw=="
PIN_BLOCK="wwDqlp2ZVcpImL8TdYZ3wg=="

echo "PIN Block (Base64): $PIN_BLOCK"
PIN_BLOCK_HEX=$(echo "$PIN_BLOCK" | base64 -d | xxd -p -c 256)
echo "PIN Block (Hex): $PIN_BLOCK_HEX"

echo "Salt (Base64): $SALT"
SALT_HEX=$(echo "$SALT" | base64 -d | xxd -p -c 256)
echo "Salt (Hex): $SALT_HEX"
        