#!/bin/bash

KEY_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/7aigu2dctluf2k3o"
CIPHERED_DATA="RxnK6NDu8RHT8/j/g9i2LNaYTCNvUemwEJ09C1AkxtCj0Ke+CKqL5qPfEC2t/ONEIUWm7Kw6Nf3vuVjrdOx74ZsHhtXTIF9SweTYdxuc3Jg3k5YYGeTkNK/OXv6AjhOlVVuSyfxs4/8LdXln4O0HmEoeydJcofYSk0WDVLFIjpxnw7i6ZSTY6SZLHglwMrxnJYsdq9y5ni4RCqTW767Yfk7SIjlzSvWdy6qVv6pZQ4za4UMlH8c6Mgc7B/9gybQDNuTHztIypXEf6N+1QsiqBHh2uKqDrKVQxEGg0kx8vyT6w4i+v+jTsvCcrWXdd655"
IV="tNTKK6IDYOlGEzUb7lVK/g=="

IV_HEX=$(echo "$IV" | base64 -d | xxd -p -c 256)
CIPHERED_DATA_HEX=$(echo "$CIPHERED_DATA" | base64 -d | xxd -p -c 256)

echo "Ciphered Data (Base64): $CIPHERED_DATA"
echo "Ciphered Data (Hex): $CIPHERED_DATA_HEX"

echo "IV (Base64): $IV"
echo "IV (Hex): $IV_HEX"

aws payment-cryptography-data decrypt-data \
    --key-identifier $KEY_ARN \
    --cipher-text $CIPHERED_DATA_HEX \
    --decryption-attributes '{
        "Symmetric": {
            "Mode": "CBC",
            "InitializationVector": "'$IV_HEX'"
        }
    }'
        