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

echo "Signing with mechanism: $P2C_MECHANISM"

# Derive key path from certificate path
KEY="${P2C_CERT/.pem/.key}"

# Get the directory where the key is located
KEY_DIR=$(dirname "$KEY")

# plain signature
openssl dgst -sha256 -sign "$KEY" -out "$P2C_SIG" "$P2C_DATA"

# Verify plain the signature
openssl dgst -sha256 -out $P2C_DATA.sha256 -binary $P2C_DATA
openssl pkeyutl -verify -pkeyopt digest:sha256 -certin -inkey $P2C_CERT -in $P2C_DATA.sha256 -sigfile $P2C_SIG
