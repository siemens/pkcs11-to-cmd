#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Hubert Hardes <hubert.hardes@siemens.com>
#
#

set -euo pipefail

source "$(dirname "$0")/common.sh"

cd "$TEST_WORK_DIR"

KEY_NAME="test_ssh_key"

# 1. generate SSH-Key to be signed
ssh-keygen -t rsa -b 2048 -N "" -f "$KEY_NAME" > /dev/null

export P2C_SLOT_CERT_0="$TEST_KEY_DIR/ed25519.pem" # this is our CA certificate
export P2C_CMD="$SCRIPT_DIR/cmds/sign-cmd-pkeyutl.sh"
export P2C_DATA="$TEST_WORK_DIR/data.bin"
export P2C_SIG="$TEST_WORK_DIR/sig.bin"

# 2. Export the public key of the signer certificate (CA) in OpenSSH format
ssh-keygen -D "$PKCS11_MODULE" > "$TEST_KEY_DIR/ed25519.openssh.pub"

# sign the public ssh key with private key of the CA
# ssh-keygen uses $TEST_KEY_DIR/ed25519.openssh.pub to find the matching private key in the PKCS#11 module
ssh-keygen -s "$TEST_KEY_DIR/ed25519.openssh.pub" -D "$PKCS11_MODULE" -I test_user -n testuser -V +1h -z 1  "$KEY_NAME.pub"

# print the signed certificate
echo "Signed SSH certificate:"
ssh-keygen -L -f "$KEY_NAME-cert.pub"
