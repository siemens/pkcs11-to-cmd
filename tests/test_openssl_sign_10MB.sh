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

export TMPDATA="$TEST_WORK_DIR/hello_world.txt"
export TMPSIG="$TEST_WORK_DIR/hello_world.sig"

export P2C_SLOT_CERT_0="$TEST_KEY_DIR/rsa.pem"
export P2C_SLOT_CERT_1="$TEST_KEY_DIR/rsa.pem"

export P2C_CMD="$SCRIPT_DIR/cmds/sign-cmd-pkeyutl.sh"
export P2C_DATA="$TEST_WORK_DIR/p2c.data"
export P2C_SIG="$TEST_WORK_DIR/p2c.sig"

# Prepare test data
dd if=/dev/random of="$TMPDATA" bs=1M count=10

openssl dgst -sha256 -out $TMPDATA.sha256 -binary $TMPDATA

# Set the PKCS#11 module path
export PKCS11_MODULE_PATH=$PKCS11_MODULE

openssl pkeyutl -engine pkcs11 -keyform engine \
  -sign -inkey "pkcs11:token=pkcs11-to-cmd-0" \
  -out "$TMPSIG" -in "$TMPDATA.sha256"

# Verify plain the signature
openssl pkeyutl -verify -certin -inkey $P2C_SLOT_CERT_0 -in $TMPDATA.sha256 -sigfile $TMPSIG
