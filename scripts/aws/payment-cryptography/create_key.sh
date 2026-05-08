#!/bin/bash

aws payment-cryptography create-key \
    --key-attributes '{
        "KeyAlgorithm": "AES_128",
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