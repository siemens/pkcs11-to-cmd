/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 *   Eugen Kremer <eugen.kremer@siemens.com>
 */

#include "debug.hpp"
#include "consts.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <string>

#ifdef NDEBUG
bool debug_enabled = false;
#else
bool debug_enabled = true;
#endif

void debug(const char* fmt, ...)
{
    va_list args;

    if (!debug_enabled) {
        return;
    }

    va_start(args, fmt);
    vfprintf(stderr, (std::string(PROVIDER_NAME) + ": " + std::string(fmt) + "\n").c_str(), args);
    va_end(args);
}
