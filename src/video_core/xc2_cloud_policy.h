// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdlib>

#include "common/common_types.h"

namespace VideoCore {

[[nodiscard]] constexpr bool IsXenoblade2CloudTitle(u64 program_id) noexcept {
    return program_id == 0x0100E95004038000ULL || program_id == 0x0400E95004038001ULL;
}

/// EDEN_NX2_NO_XC2_CLOUDS=1 turns the cloud workarounds off, for A/B comparisons.
[[nodiscard]] inline bool IsXenoblade2CloudPolicyEnabled(u64 program_id) noexcept {
    if (!IsXenoblade2CloudTitle(program_id)) {
        return false;
    }
    const char* const value = std::getenv("EDEN_NX2_NO_XC2_CLOUDS");
    return value == nullptr || value[0] == '\0' || value[0] == '0';
}

} // namespace VideoCore
