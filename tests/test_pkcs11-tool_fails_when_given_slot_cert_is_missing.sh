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

TOKEN_LABEL="pkcs11-to-cmd-0"
PUBLIC_KEY_FILE="$TEST_WORK_DIR/$SCRIPT_NAME-public_key"

export P2C_SLOT_CERT_0="$SCRIPT_DIR/cmds/does_not_exist.pem"

# Expect export operation to fail because the certificate file does not exist
output=$(pkcs11-tool --module "$PKCS11_MODULE" -r --type pubkey --slot 0 --label "$TOKEN_LABEL" -o "$PUBLIC_KEY_FILE.der" 2>&1)

expect_failed_with "$output" "Invalid certificate file:"
