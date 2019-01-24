#!/bin/bash
echo "Cisco Encrypted Debug Data Decryption Script!"
if [ $# -eq 0 ]
  then
    echo "use: $0 /path/to/debug.enc"
    exit;
fi
echo "{+} Decrypting $1"
OUT="$1.decrypted.tar.gz"
openssl aes-128-cbc -salt -md md5 -d -k 'NKDebug12#$%' < $1 > $OUT
echo "{+} Plaintext should be at $OUT...
