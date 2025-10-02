#pragma once

#ifndef NVTX_HELPERS_H
#define NVTX_HELPERS_H

#include <nvtx3/nvToolsExt.h>

#ifdef __cplusplus
extern "C" {
#endif

// توابع کمکی برای NVTX profiling
void nvtx_start_range(const char* name, uint32_t color);
void nvtx_end_range();

// توابع برای marking
void nvtx_mark(const char* message, uint32_t color);

// رنگ‌های پیش‌فرض
#define NVTX_COLOR_RED  0xFF0000FF
#define NVTX_COLOR_GREEN  0x00FF00FF
#define NVTX_COLOR_BLUE  0x0000FFFF
#define NVTX_COLOR_YELLOW  0xFFFF00FF
#define NVTX_COLOR_PURPLE  0xFF00FFFF

#ifdef __cplusplus
}
#endif

#endif // NVTX_HELPERS_H