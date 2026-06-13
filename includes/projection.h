#pragma once

#ifndef PROJECTION_H
#define PROJECTION_H

#include "event.h"
#include "attacker.h"
#include <stdint.h>
#include <pthread.h>

/** @brief
 *
 * 投影层 — 从不可变事件流构建当前状态
 * 替代 monitor.c 中的原始链表管理
 */

/** @brief
 *
 * 攻击者投影 — 由事件流驱动
 * 保留 Attacker 结构体作为输出, 与 monitor.h 接口兼容
 */
typedef struct {
    Attacker *head;                          /* 攻击者链表头 */
    pthread_mutex_t lock;                    /* 线程安全锁 */
    uint64_t last_applied_seq;               /* 最后应用的事件 seq */
} AttackerProjection;

/** @brief
 *
 * 统计投影 — 按事件类型的全局计数
 */
typedef struct {
    uint64_t total_events;                   /* 事件总数 */
    uint64_t by_type[0x10];                  /* 按事件类型计数 */
    uint64_t by_port[0x10000];               /* 按端口计数 (索引 = port) */
    uint64_t tcp_syn_count;                  /* SYN 包总数 */
    uint64_t http_count;                     /* HTTP 请求总数 */
    uint64_t ssh_count;                      /* SSH 尝试总数 */
    uint64_t scan_alerts;                    /* 扫描告警总数 */
    uint64_t flood_alerts;                   /* 泛洪告警总数 */
    pthread_mutex_t lock;
    uint64_t last_applied_seq;
} StatsProjection;

/** @brief
 *
 * 初始化攻击者投影
 */
int attacker_projection_init(AttackerProjection *ap);

/** @brief
 *
 * 初始化统计投影
 */
int stats_projection_init(StatsProjection *sp);

/** @brief
 *
 * 对两个投影同时应用一条事件 (线程安全)
 * 这是实时事件的主入口
 */
void projection_apply(AttackerProjection *ap, StatsProjection *sp, const Event *e);

/** @brief
 *
 * 从 event store 完全重建所有投影
 * 在启动时调用
 * return 0x0 成功
 */
int projection_rebuild(AttackerProjection *ap, StatsProjection *sp);

/** @brief
 *
 * 获取 Top-N 攻击者 (返回副本数组, 调用者 free)
 */
int attacker_projection_get_top(AttackerProjection *ap, Attacker **out, int max);

/** @brief
 *
 * 销毁攻击者投影, 释放所有节点
 */
void attacker_projection_destroy(AttackerProjection *ap);

/** @brief
 *
 * 销毁统计投影
 */
void stats_projection_destroy(StatsProjection *sp);

#endif
