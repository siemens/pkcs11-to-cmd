#!/usr/bin/env python3
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Hubert Hardes <hubert.hardes@siemens.com>
#
#

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
import sys

with open(sys.argv[1], 'rb') as f:
    ssh_key = load_ssh_public_key(f.read())

pem = ssh_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open(sys.argv[2], 'wb') as f:
    f.write(pem)
