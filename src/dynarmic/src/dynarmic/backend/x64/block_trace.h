// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "common/common_types.h"
#include "dynarmic/ir/terminal.h"

namespace Dynarmic::Backend::X64 {

/// LICHII_BLOCK_TRACE=<path>: every guest basic block the A64 JIT compiles is appended to <path>
/// as one JSON line: {"pc","end","term","next":[...],"thread"}. "term" is one of link, indirect,
/// ret, halt, cond. "next" holds the static successors. Blocks are written once per (pc, end).
/// Off by default; the only cost then is one cached bool per compiled block.
bool BlockTraceEnabled() noexcept;

void BlockTraceRecord(u64 pc, u64 end_pc, const IR::Term::Terminal& terminal) noexcept;

} // namespace Dynarmic::Backend::X64
