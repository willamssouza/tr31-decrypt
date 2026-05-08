#!/bin/bash

KEK_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/xf22cier2atsm5n7"

aws payment-cryptography get-key \
    --key-identifier $KEK_ARN \
    --region us-east-1