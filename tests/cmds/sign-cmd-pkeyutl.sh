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

# sign hashed data
openssl pkeyutl -sign -inkey "$KEY" -in "$P2C_DATA" -out "$P2C_SIG"

# Verify plain the signature
openssl pkeyutl -verify -certin -inkey $P2C_CERT -in $P2C_DATA -sigfile $P2C_SIG
