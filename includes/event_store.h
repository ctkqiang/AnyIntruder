#pragma once

#ifndef EVENT_STORE_H
#define EVENT_STORE_H

#include "event.h"
#include <stdio.h>
#include <stdint.h>

/** @brief
 *
 * Append-only 事件存储 — Event Sourcing 持久化层
 * 所有事件以 JSONL 格式写入, 内存索引支持 O(1) 随机访问
 */

/** @brief
 *
 * 回放回调 — 每条事件调用一次
 * return 0x0 继续, 非零停止回放
 */
typedef int (*event_replay_cb)(const Event *e, void *ctx);

/** @brief
 *
 * 初始化事件存储
 * path 为 NULL 时使用默认 EVENT_STORE_FILE
 * return 0x0 成功, 非零失败
 */
int event_store_init(const char *path);

/** @brief
 *
 * 追加一条不可变事件到存储 (线程安全)
 * 自动分配 seq 和 version
 * return 0x0 成功, 非零失败
 */
int event_store_append(Event *e);

/** @brief
 *
 * 从指定 seq 开始回放事件
 * callback 返回非零时停止
 * return 已回放的事件数
 */
int event_store_replay(uint64_t from_seq, event_replay_cb callback, void *ctx);

/** @brief
 *
 * 获取最新事件序列号
 * return 0 表示没有事件
 */
uint64_t event_store_get_latest_seq(void);

/** @brief
 *
 * 获取存储文件大小 (字节)
 */
size_t event_store_get_size(void);

/** @brief
 *
 * 获取事件总数
 */
uint64_t event_store_get_count(void);

/** @brief
 *
 * 导出事件到文件 (JSON 数组格式)
 */
int event_store_export(const char *path, uint64_t from_seq, uint64_t to_seq);

/** @brief
 *
 * 关闭存储, 释放索引
 */
void event_store_shutdown(void);

#endif
