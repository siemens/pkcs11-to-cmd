#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Eugen Kremer <eugen.kremer@siemens.com>
#
#
# This test creates a minimal RAUC bundle using rauc bundle, sign it initially, and then re-sign it

set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

BUNDLE="$TEST_WORK_DIR/minimal-bundle.raucb"
RESIGNED_BUNDLE="$TEST_WORK_DIR/minimal-bundle-resigned.raucb"
BUNDLE_DIR="$TEST_WORK_DIR/bundle-dir"

# Create minimal bundle directory structure
mkdir -p "$BUNDLE_DIR"
mkdir -p "$TEST_WORK_DIR/rootfsdir"
head -c 1M </dev/urandom > "$TEST_WORK_DIR/rootfsdir/dummy.txt"
mksquashfs "$TEST_WORK_DIR/rootfsdir" "$BUNDLE_DIR/rootfs.img" -noappend -comp gzip > /dev/null

cat > "$BUNDLE_DIR/manifest.raucm" <<EOF
[update]
compatible=demo

[bundle]
format=verity

[image.rootfs]
filename=rootfs.img
EOF

# Initial bundle signing (EC)
rauc bundle \
  --cert "$TEST_KEY_DIR/ec.pem" \
  --key "$TEST_KEY_DIR/ec.key" \
  --keyring "$TEST_KEY_DIR/ec.pem" \
  "$BUNDLE_DIR" "$BUNDLE"

echo "Initial bundle created: $BUNDLE"

# Re-signing with RSA
export P2C_CMD=$SCRIPT_DIR/cmds/sign-cmd-rsautl.sh
export P2C_DATA=$TEST_WORK_DIR/data.bin
export P2C_SIG=$TEST_WORK_DIR/data.sig
export RAUC_PKCS11_PIN=1234
export P2C_SLOT_CERT_0=$TEST_KEY_DIR/rsa.pem
export RAUC_PKCS11_MODULE=$PKCS11_MODULE

rauc resign \
  --no-verify \
  --cert "pkcs11:serial=sn-0" \
  --key "pkcs11:serial=sn-0" \
  --keyring "$TEST_KEY_DIR/rsa.pem" \
  "$BUNDLE" "$RESIGNED_BUNDLE"

echo "Re-signed bundle created: $RESIGNED_BUNDLE"
