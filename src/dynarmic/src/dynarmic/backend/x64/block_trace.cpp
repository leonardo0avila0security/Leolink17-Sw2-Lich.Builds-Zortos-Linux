// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dynarmic/backend/x64/block_trace.h"

#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unordered_set>
#include <variant>
#include <vector>

#include <fmt/format.h>

#include "dynarmic/frontend/A64/a64_location_descriptor.h"

namespace Dynarmic::Backend::X64 {
namespace {

struct Sink {
    std::FILE* file = nullptr;
    std::mutex mutex;
    std::unordered_set<u64> seen;

    Sink() {
        if (const char* path = std::getenv("LICHII_BLOCK_TRACE"); path != nullptr && path[0] != '\0') {
            file = std::fopen(path, "ab");
        }
    }
    ~Sink() {
        if (file != nullptr) {
            std::fclose(file);
        }
    }
};

Sink& GetSink() {
    static Sink sink;
    return sink;
}

struct Info {
    const char* kind = "none";
    std::vector<u64> next;
    bool conditional = false;
};

void Leaf(const IR::Term::LeafTerminal& leaf, Info& info) {
    std::visit(
        [&](const auto& t) {
            using T = std::decay_t<decltype(t)>;
            if constexpr (std::is_same_v<T, IR::Term::LinkBlock> ||
                          std::is_same_v<T, IR::Term::LinkBlockFast>) {
                info.next.push_back(A64::LocationDescriptor{t.next}.PC());
                if (info.kind[0] == 'n') {
                    info.kind = "link";
                }
            } else if constexpr (std::is_same_v<T, IR::Term::PopRSBHint>) {
                info.kind = "ret";
            } else if constexpr (std::is_same_v<T, IR::Term::ReturnToDispatch> ||
                                 std::is_same_v<T, IR::Term::FastDispatchHint>) {
                info.kind = "indirect";
            }
        },
        leaf);
}

} // Anonymous namespace

bool BlockTraceEnabled() noexcept {
    static const bool enabled = GetSink().file != nullptr;
    return enabled;
}

void BlockTraceRecord(u64 pc, u64 end_pc, const IR::Term::Terminal& terminal, bool is_call) noexcept {
    Sink& sink = GetSink();
    if (sink.file == nullptr) {
        return;
    }
    Info info;
    std::visit(
        [&](const auto& t) {
            using T = std::decay_t<decltype(t)>;
            if constexpr (std::is_same_v<T, IR::Term::LeafTerminal>) {
                Leaf(t, info);
            } else if constexpr (std::is_same_v<T, IR::Term::If> ||
                                 std::is_same_v<T, IR::Term::CheckBit>) {
                info.conditional = true;
                Leaf(t.then_, info);
                Leaf(t.else_, info);
            } else if constexpr (std::is_same_v<T, IR::Term::CheckHalt>) {
                Leaf(t.else_, info);
            }
        },
        terminal);

    std::string next;
    for (const u64 target : info.next) {
        next += fmt::format("{}\"0x{:x}\"", next.empty() ? "" : ",", target);
    }
    const std::string line = fmt::format(
        "{{\"pc\":\"0x{:x}\",\"end\":\"0x{:x}\",\"term\":\"{}\",\"cond\":{},\"call\":{},\"next\":[{}]}}\n",
        pc, end_pc, info.kind, info.conditional ? "true" : "false", is_call ? "true" : "false", next);

    std::scoped_lock lock{sink.mutex};
    if (!sink.seen.insert(pc ^ (end_pc * 0x9E3779B97F4A7C15ull)).second) {
        return;
    }
    std::fwrite(line.data(), 1, line.size(), sink.file);
}

} // namespace Dynarmic::Backend::X64
