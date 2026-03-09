#!/bin/bash

PEK_INBOUND_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/42z2ubycrryx6iqo"
PEK_OUTBOUND_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/6eirptzmktdklwek"
PIN_BLOCK="lyeWoJUj981ojoSMnCDxKQ=="
PAN="36070500100715"

PIN_BLOCK_HEX=$(echo "$PIN_BLOCK" | base64 -d | xxd -p -c 256 | tr '[:lower:]' '[:upper:]')
echo "PIN Block (Hex): $PIN_BLOCK_HEX"

aws payment-cryptography-data translate-pin-data \
    --encrypted-pin-block "$PIN_BLOCK_HEX" \
    --incoming-translation-attributes IsoFormat4="{PrimaryAccountNumber=$PAN}" \
    --incoming-key-identifier "$PEK_INBOUND_ARN" \
    --outgoing-translation-attributes IsoFormat4="{PrimaryAccountNumber=$PAN}" \
    --outgoing-key-identifier "$PEK_OUTBOUND_ARN"
