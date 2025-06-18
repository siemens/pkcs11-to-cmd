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

# print data file statistics
ls -la "$P2C_DATA"

# sign data as is without any modification
# the result container does not contain any metadata so that it could be verified
openssl rsautl -sign -inkey "$KEY" -in "$P2C_DATA" -out "$P2C_SIG"
