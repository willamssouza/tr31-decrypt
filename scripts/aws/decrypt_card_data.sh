#!/bin/bash

KEY_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/2z4vw3xz4xsfsjsf"
CIPHERED_DATA="fjPMAKB4z+knxnGd7eah5ZBV8N5DB7nSTOfshBjaa8KezkIMWiJeJqHf5J2hiu90qCHn64b/cYhRpcGiSAMw9uITeanWJMBNdYgerlD3r/KsCN02lh1MnKVcSH/MLL2xqrw36Dai4wqLyfikCuY2x2S/nGGGt7A2Dg4h+3TCmtoV5kKmGhM5ns7gDBihmU2nnvZ0JGGoIhMaZpibfvfRCigq+XJe1AWcklSBRJfQLLTKxTzTpQ9B7lHX3RRIBnj1"
IV="XEWxSVlKQBYfkTpo9tukQQ=="

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
        