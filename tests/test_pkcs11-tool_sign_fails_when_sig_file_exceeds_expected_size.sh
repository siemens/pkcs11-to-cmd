#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Eugen Kremer <eugen.kremer@siemens.com>
#
#

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

export TMPDATA="$TEST_WORK_DIR/hello_world.txt"
export TMPSIG="$TEST_WORK_DIR/hello_world.sig"
export PIN="1234"

export P2C_SLOT_CERT_0="$TEST_KEY_DIR/rsa.pem"

export P2C_CMD="$SCRIPT_DIR/cmds/sign-cmd-do-nothing.sh"
export P2C_DATA="$TEST_WORK_DIR/p2c.data"
export P2C_SIG="$TEST_WORK_DIR/to-big-signature.sig"

# Prepare test data
echo "hello world" > "$TMPDATA"

# Create a signature file that is larger than the expected size
dd if=/dev/urandom of="$P2C_SIG" bs=1 count=513 2>/dev/null

output=$(pkcs11-tool --slot-index 0 -s -p $PIN -m SHA256-RSA-PKCS --module $PKCS11_MODULE --input-file $TMPDATA --output-file $TMPSIG 2>&1)

expect_failed_with "$output" "\\[512\\] too small or invalid signature size=513"
