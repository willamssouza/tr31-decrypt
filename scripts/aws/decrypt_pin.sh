#!/bin/bash

PEK_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/xf22cier2atsm5n7"
SALT="kQ66ffUuY1XjAsvX02M0Cw=="
PIN_BLOCK="wwDqlp2ZVcpImL8TdYZ3wg=="
PAN="4761739001010119"

PIN_BLOCK_HEX=$(echo "$PIN_BLOCK" | base64 -d | xxd -p -c 256)
echo "PIN Block (Hex): $PIN_BLOCK_HEX"

SALT_HEX=$(echo "$SALT" | base64 -d | xxd -p -c 256)
echo "Salt (Hex): $SALT_HEX"

aws payment-cryptography-data verify-pin-data \
    --verification-key-identifier $PEK_ARN \
    --encryption-key-identifier $PEK_ARN \
    --primary-account-number $PAN \
    --pin-block-format ISO_FORMAT_4 \
    --verification-attributes VisaPin="{PinVerificationKeyIndex=1,VerificationValue=5507}" \
    --encrypted-pin-block $PIN_BLOCK_HEX 
