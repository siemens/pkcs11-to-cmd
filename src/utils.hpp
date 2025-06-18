/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 *   Eugen Kremer <eugen.kremer@siemens.com>
 */

#pragma once

#include <string>
#include <vector>

enum enumerable_objects {
    // UNDEFINED = 0, value 0 is reserved for undefined objects
    public_key = 1,
    private_key = 2,
    certificate = 3
};

std::vector<std::string> getSlots();
bool isValidFile(const std::string& path);
template <typename T>
std::vector<u_int8_t> significantBytes(const T& data)
{
    std::vector<u_int8_t> result;

    // skip leading zero bytes
    for (size_t i = 0; i < sizeof(T); ++i) {
        u_int8_t byte = (data >> ((sizeof(T) - i - 1) * 8)) & 0xFF;
        if (byte != 0 || !result.empty()) {
            result.push_back(byte);
        }
    }

    if (result.empty()) {
        result.push_back(0); // ensure at least one byte is present
    }

    return result;
}
void fclose_conditional(FILE* f);
