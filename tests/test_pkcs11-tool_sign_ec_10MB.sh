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
export PIN="1234"

export P2C_SLOT_CERT_0="$TEST_KEY_DIR/ec.pem"

export P2C_CMD="$SCRIPT_DIR/cmds/sign-cmd.sh"
export P2C_DATA="$TEST_WORK_DIR/p2c.data"
export P2C_SIG="$TEST_WORK_DIR/p2c.sig"

# Prepare test data
dd if=/dev/random of="$TMPDATA" bs=1M count=10

pkcs11-tool --slot-index 0 -s -p $PIN -m ECDSA-SHA256 --module $PKCS11_MODULE --input-file $TMPDATA --output-file $TMPSIG

# Verify the ECDSA signature
openssl dgst -sha256 -out $TMPDATA.sha256 -binary $TMPDATA
openssl pkeyutl -verify -pkeyopt digest:sha256 -certin -inkey $P2C_SLOT_CERT_0 -in $TMPDATA.sha256 -sigfile $TMPSIG
