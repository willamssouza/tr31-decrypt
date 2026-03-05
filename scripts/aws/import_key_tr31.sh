#!/bin/bash

KEK_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/xtq4auqn5z34fwh2"
TR31_KEY_BLOCK="D0112P0AD00E00002e9e2c5368e77cd09754e482234b876004cacb8486f842502edbabc8ae7679c23cb8489da59ae50269e8132fd98a75a4"

aws payment-cryptography import-key \
    --key-material '{
        "Tr31KeyBlock": {
            "WrappingKeyIdentifier": "'$KEK_ARN'",
            "WrappedKeyBlock": "'$TR31_KEY_BLOCK'"
        }
    }' \
    --enabled \
    --region us-east-1