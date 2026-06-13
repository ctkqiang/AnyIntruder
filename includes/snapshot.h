#pragma once

#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include "projection.h"
#include <stdint.h>

/** @brief
 *
 * 快照管理 — 定期保存投影状态, 加速启动恢复
 */

/** @brief
 *
 * 初始化快照系统
 */
int snapshot_init(const char *dir);

/** @brief
 *
 * 尝试从最新快照恢复投影状态
 * return 已恢复的快照 seq, 0 表示无快照可用
 */
uint64_t snapshot_load(AttackerProjection *ap, StatsProjection *sp);

/** @brief
 *
 * 保存当前投影状态快照
 * 在 snapshot_init 的目录下创建 snapshot_<seq>.db
 * return 0x0 成功
 */
int snapshot_save(AttackerProjection *ap, const StatsProjection *sp, uint64_t seq);

/** @brief
 *
 * 检查是否应该生成快照 (按事件数或时间间隔)
 * return 0x1 应该快照, 0x0 不需要
 */
int snapshot_should_save(uint64_t current_seq, uint64_t last_snapshot_seq, time_t last_snapshot_ts);

/** @brief
 *
 * 清理旧快照, 保留最近 N 个
 */
void snapshot_cleanup(void);

/** @brief
 *
 * 关闭快照系统
 */
void snapshot_shutdown(void);

#endif
