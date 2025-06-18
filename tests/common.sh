#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Eugen Kremer <eugen.kremer@siemens.com>
#
#
# This file is to be sourced by other scripts

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0" .sh)"
PKCS11_MODULE="$SCRIPT_DIR/../build/libpkcs11-to-cmd.so"
TEST_WORK_DIR=$(mktemp --directory "/tmp/${SCRIPT_NAME}.XXXXXX")
TEST_KEY_DIR="$TEST_WORK_DIR/keys"

mkdir -p "$TEST_KEY_DIR"

trap 'rm -rf "$TEST_WORK_DIR"' EXIT

# create ec and rsa keys and certificates in $TEST_KEY_DIR
generate_keys() {
    echo "Generating EC key and certificate..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$TEST_KEY_DIR/ec.key"
    openssl req -new -x509 -key "$TEST_KEY_DIR/ec.key" -out "$TEST_KEY_DIR/ec.pem" -days 3650 -subj "/CN=Test EC Key"
    export TEST_EC_KEY="$TEST_KEY_DIR/ec.key"
    export TEST_EC_CERT="$TEST_KEY_DIR/ec.pem"

    echo "Generating RSA key and certificate..."
    openssl genpkey -algorithm RSA -out "$TEST_KEY_DIR/rsa.key" -pkeyopt rsa_keygen_bits:2048
    openssl req -new -x509 -key "$TEST_KEY_DIR/rsa.key" -out "$TEST_KEY_DIR/rsa.pem" -days 3650 -subj "/CN=Test RSA Key"
    export TEST_RSA_KEY="$TEST_KEY_DIR/rsa.key"
    export TEST_RSA_CERT="$TEST_KEY_DIR/rsa.pem"
}

generate_keys

# Expect a command to fail and output to contain expected string
expect_failed_with() {
    local status=$?
    local output="$1"
    local expected="$2"
    if [ $status -eq 0 ]; then
        echo "Expected failure, but command succeeded."
        echo "$output"
        exit 1
    fi
    if grep -q "$expected" <<< "$output"; then
        echo "Command failed as expected with: $expected"
    else
        echo "Command failed, but not with expected message: $expected"
        echo "$output"
        exit 1
    fi
}

# Expect a command to succeed and output to contain expected string
expect_succeeded_with() {
    local status=$?
    local output="$1"
    local expected="$2"
    if [ ! $status -eq 0 ]; then
        echo "Expected command to succeed."
        echo "$output"
        exit 1
    fi
    if grep -q "$expected" <<< "$output"; then
        echo "Command succeeded as expected with: $expected"
    else
        echo "Command succeeded, but not with expected message: $expected"
        echo "$output"
        exit 1
    fi
}

