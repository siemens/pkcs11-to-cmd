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

TOKEN_LABEL="pkcs11-to-cmd-"

export P2C_SLOT_CERT_0="$TEST_KEY_DIR/rsa.pem"
# should fill gaps export P2C_SLOT_CERT_1="$TEST_KEY_DIR/rsa.pem"
export P2C_SLOT_CERT_2="$TEST_KEY_DIR/ec.pem"

OUTPUT=$(pkcs11-tool --module "$PKCS11_MODULE" -L)

# Check: Slot 0,1 vorhanden
if ! echo "$OUTPUT" | grep -q "Slot 0"; then
  echo "[FAIL] Slot 0 not found"
  exit 1
else
  echo "[PASS] Slot 0 found"
fi

if ! echo "$OUTPUT" | grep -q "Slot 2"; then
  echo "[FAIL] Slot 2 not found"
  exit 1
else
  echo "[PASS] Slot 2 found"
fi

# Check: Token Label = TestToken
if ! echo "$OUTPUT" | grep -q "token label *: *$TOKEN_LABEL"; then
  echo "[FAIL] Token Label is not '$TOKEN_LABEL'"
  exit 1
else
  echo "[PASS] Token Label is '$TOKEN_LABEL'"
fi
