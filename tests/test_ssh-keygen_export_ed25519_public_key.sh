#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Hubert Hardes <hubert.hardes@siemens.com>
#
#

set -e

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

PUBLIC_KEY_FILE="$TEST_WORK_DIR/$SCRIPT_NAME-my_ed25519_0"

export P2C_SLOT_CERT_0="$TEST_KEY_DIR/ed25519.pem"

ssh-keygen -D "$PKCS11_MODULE" > $PUBLIC_KEY_FILE.openssh.pub

# convert ssh public key to PEM format
$SCRIPT_DIR/convert_ssh-pubkey_to_pkcs8.py $PUBLIC_KEY_FILE.openssh.pub $PUBLIC_KEY_FILE.pub

# currently not implemented in ssh-keygen:
# ssh-keygen -e -m PKCS8 -f $PUBLIC_KEY_FILE.openssh.pub > $PUBLIC_KEY_FILE.pub
# obtaining output: "do_convert_to_pkcs8: unsupported key type ED25519"

# extract public key from PEM file
openssl x509 -in "$P2C_SLOT_CERT_0" -pubkey -noout > $PUBLIC_KEY_FILE.original.pem

# the other way around also isn't implemented in ssh-keygen:
# ssh-keygen -i -m PKCS8 -f $PUBLIC_KEY_FILE.original.pem > $PUBLIC_KEY_FILE.openssh-expected.pub
# obtaining output: "do_convert_from_pkcs8: unsupported pubkey type 1087"

diff $PUBLIC_KEY_FILE.original.pem $PUBLIC_KEY_FILE.pub
