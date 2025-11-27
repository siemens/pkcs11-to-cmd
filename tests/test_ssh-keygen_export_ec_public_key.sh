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

PUBLIC_KEY_FILE="$TEST_WORK_DIR/$SCRIPT_NAME-my_ec_0"

export P2C_SLOT_CERT_0="$TEST_KEY_DIR/ec.pem"

ssh-keygen -D "$PKCS11_MODULE" > $PUBLIC_KEY_FILE.openssh.pub

# convert ssh public key to PEM format
ssh-keygen -e -m PKCS8 -f $PUBLIC_KEY_FILE.openssh.pub > $PUBLIC_KEY_FILE.pub

# extract public key from PEM file
openssl x509 -in "$P2C_SLOT_CERT_0" -pubkey -noout > $PUBLIC_KEY_FILE.original.pem

diff $PUBLIC_KEY_FILE.original.pem $PUBLIC_KEY_FILE.pub
