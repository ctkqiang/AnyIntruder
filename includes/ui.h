#pragma once

#ifndef UI_H
#define UI_H

#include "projection.h"
#include "stats.h"

int ui_run(void);

/** @brief
 *
 * 注入统计引用 — main() 在 UI 启动前调用
 */
void ui_set_stats_refs(const StatsProjection *sp, RateTracker *rt);

#endif
