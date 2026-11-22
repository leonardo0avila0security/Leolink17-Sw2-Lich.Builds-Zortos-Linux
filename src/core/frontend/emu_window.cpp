// SPDX-FileCopyrightText: Copyright 2025 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: 2014 Citra Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <mutex>
#include "core/frontend/emu_window.h"

namespace Core::Frontend {

EmuWindow::EmuWindow() {
    // TODO: Find a better place to set this.
    config.min_client_area_size =
        std::make_pair(Layout::MinimumSize::Width, Layout::MinimumSize::Height);
    active_config = config;
}

EmuWindow::~EmuWindow() {}

std::pair<f32, f32> EmuWindow::MapToTouchScreen(u32 framebuffer_x, u32 framebuffer_y) const {
    const auto layout = GetFramebufferLayout();
    framebuffer_x = (std::max)(framebuffer_x, layout.screen.left);
    framebuffer_x = (std::min)(framebuffer_x, layout.screen.right - 1);
    framebuffer_y = (std::max)(framebuffer_y, layout.screen.top);
    framebuffer_y = (std::min)(framebuffer_y, layout.screen.bottom - 1);
    const float x =
        static_cast<float>(framebuffer_x - layout.screen.left) /
        static_cast<float>(layout.screen.right - layout.screen.left);
    const float y =
        static_cast<float>(framebuffer_y - layout.screen.top) /
        static_cast<float>(layout.screen.bottom - layout.screen.top);

    return std::make_pair(x, y);
}

std::pair<u32, u32> EmuWindow::ClipToTouchScreen(u32 new_x, u32 new_y) const {
    const auto layout = GetFramebufferLayout();
    new_x = (std::max)(new_x, layout.screen.left);
    new_x = (std::min)(new_x, layout.screen.right - 1);

    new_y = (std::max)(new_y, layout.screen.top);
    new_y = (std::min)(new_y, layout.screen.bottom - 1);

    return std::make_pair(new_x, new_y);
}

void EmuWindow::UpdateCurrentFramebufferLayout(u32 width, u32 height) {
    NotifyFramebufferLayoutChanged(Layout::DefaultFrameLayout(width, height));
}

} // namespace Core::Frontend
