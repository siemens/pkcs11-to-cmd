# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (C) 2025 Siemens
#
# Authors:
#  Eugen Kremer <eugen.kremer@siemens.com>

FROM gcc:14.2.0-bookworm
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update --fix-missing \
    && apt install -y --no-install-recommends cmake ccache lcov \
    libp11-kit-dev \
    bsdextrautils opensc libengine-pkcs11-openssl dumpasn1 gnutls-bin squashfs-tools rauc python3-pip xxd \
    && apt clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install reuse --break-system-packages

ENV PATH=/usr/local/bin/reuse:$PATH
