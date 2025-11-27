#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Eugen Kremer <eugen.kremer@siemens.com>
#
#

set -e

# env | grep -i 'P2C_' | sort


# Derive key path from certificate path
KEY="${P2C_CERT/.pem/.key}"

# Get the directory where the key is located
KEY_DIR=$(dirname "$KEY")

# PKCS#11 sends signature input for RSA in ASN.1 encoding
if (openssl asn1parse -inform DER -in "$P2C_DATA" 2> /dev/null) | grep -q 'SEQUENCE'; then
   echo "$P2C_DATA ist ASN.1-coded extract raw data from DigestInfo"

   openssl asn1parse -inform DER -in "$P2C_DATA"

   hash_hex=$(openssl asn1parse -inform DER -in "$P2C_DATA" | awk '/OCTET STRING/ {sub(/^.*\[HEX DUMP\]:/, ""); print $0; exit}')
   if [ ! -n "$hash_hex" ]; then
      echo "Extraction failed"
      openssl asn1parse -inform DER -in "$P2C_DATA"
      exit 1
   fi

   echo "$hash_hex" | xxd -r -p > "${P2C_DATA}.raw"

   if [ ! -s "${P2C_DATA}.raw" ]; then
      echo "Extraction failed"
      openssl asn1parse -inform DER -in "$P2C_DATA"
      exit 1
   fi

   export P2C_DATA="${P2C_DATA}.raw"
fi

ls -l "$P2C_DATA"

# sign hashed data
openssl pkeyutl -sign -inkey "$KEY" -in "$P2C_DATA" -out "$P2C_SIG"

# Verify plain the signature
openssl pkeyutl -verify -certin -inkey $P2C_CERT -in $P2C_DATA -sigfile $P2C_SIG

# The signer returns the signature in ASN.1 format for ECDSA/EDDSA, and in DER format for RSA.
# The PKCS#11 expects the signature in DER format for RSA and in raw R|S for ECDSA/EDDSA.
if [ "$P2C_MECHANISM" == "CKM_ECDSA" ]; then
   echo "Converting ECDSA signature from asn.1 to DER format"
   
   # Determine curve from certificate if available
   curve_bytes=32  # Default for P-256
   
   if [ -f "${P2C_CERT}" ]; then
      curve_info=$(openssl x509 -in "${P2C_CERT}" -text -noout | sed -n '/Public Key Algorithm/,/Signature Algorithm/p' | grep -E "(ASN1 OID|NIST CURVE|brainpool|secp|prime)")
      
      if echo "$curve_info" | grep -q "brainpoolP512r1\|secp521r1"; then
         curve_bytes=66  # P-521
         echo "Detected P-521 curve"
      elif echo "$curve_info" | grep -q "brainpoolP384r1\|secp384r1"; then
         curve_bytes=48  # P-384
         echo "Detected P-384 curve"
      elif echo "$curve_info" | grep -q "brainpoolP256r1\|secp256r1\|prime256v1"; then
         curve_bytes=32  # P-256
         echo "Detected P-256 curve"
      else
         echo "Unknown curve, using default P-256"
      fi
      
      echo "Detected curve requiring $curve_bytes bytes per component"
   fi
   hex_chars=$((curve_bytes * 2))
   
   # openssl asn1parse -inform DER -in $P2C_SIG

   r=$(openssl asn1parse -inform DER -in $P2C_SIG | awk '/INTEGER/ {sub(/^.*:/,"",$0); print $0}' | head -1)
   s=$(openssl asn1parse -inform DER -in $P2C_SIG | awk '/INTEGER/ {sub(/^.*:/,"",$0); print $0}' | tail -1)
   
   # Use detected curve length for padding
   printf "%0*s" "$hex_chars" "$r" | tr ' ' 0 | xxd -r -p > r.bin
   printf "%0*s" "$hex_chars" "$s" | tr ' ' 0 | xxd -r -p > s.bin
   
   cat r.bin s.bin > $P2C_SIG
   
   rm r.bin s.bin
fi
