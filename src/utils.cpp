/*
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: MIT
 *
 * Authors:
 *   Eugen Kremer <eugen.kremer@siemens.com>
 */

#include "utils.hpp"

#include <regex>
#include <sys/stat.h>

bool isValidFile(const std::string& path)
{
    struct stat sb;
    return stat(path.c_str(), &sb) == 0 && S_ISREG(sb.st_mode);
}

std::vector<std::string> getSlots()
{
    std::regex re("^P2C_SLOT_CERT_([0-9]+)$");
    std::vector<std::string> slots;
    extern char** environ;
    for (char** env = environ; *env != nullptr; ++env) {
        std::string entry(*env);
        size_t eq = entry.find('=');

        if (eq == std::string::npos) {
            continue;
        }
        std::string key = entry.substr(0, eq);

        std::smatch m;

        if (std::regex_match(key, m, re)) {
            int idx = std::stoi(m[1]);

            if ((size_t)idx >= slots.size()) {
                slots.resize(idx + 1, "");
            }

            slots[idx] = entry.substr(eq + 1);
        }
    }

    return slots;
}

void fclose_conditional(FILE* f)
{
    if (f) {
        fclose(f);
    }
}
