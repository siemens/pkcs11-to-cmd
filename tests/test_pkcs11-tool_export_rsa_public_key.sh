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

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

TOKEN_LABEL="pkcs11-to-cmd-0"
PUBLIC_KEY_FILE="$TEST_WORK_DIR/$SCRIPT_NAME-public_key"

export P2C_SLOT_CERT_0="$TEST_KEY_DIR/rsa.pem"

# Export public key from our PKCS#11 provider (if implemented)
pkcs11-tool --module "$PKCS11_MODULE" -r --type pubkey --slot 0 --label "$TOKEN_LABEL" -o "$PUBLIC_KEY_FILE.der"

openssl rsa -pubin -inform DER -in "$PUBLIC_KEY_FILE.der" -outform PEM -out "$PUBLIC_KEY_FILE.pem"

openssl x509 -in "$P2C_SLOT_CERT_0" -pubkey -noout > $PUBLIC_KEY_FILE.original.pem

diff $PUBLIC_KEY_FILE.original.pem "$PUBLIC_KEY_FILE.pem"
