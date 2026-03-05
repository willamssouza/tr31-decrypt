#!/bin/bash

KEK_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/a6o2bpzd6zfolfxx"

aws payment-cryptography get-key \
    --key-identifier $KEK_ARN \
    --region us-east-1