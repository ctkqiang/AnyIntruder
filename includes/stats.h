#pragma once

#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

/** @brief
 *
 * 实时统计 — EMA 速率计算 + 热点数据
 */

/** @brief
 *
 * 统计快照 — 调用者只读
 */
typedef struct {
    double events_per_sec_1min;       /* 1 分钟 EMA 速率 */
    double events_per_sec_5min;       /* 5 分钟 EMA 速率 */
    double events_per_sec_15min;      /* 15 分钟 EMA 速率 */

    uint64_t events_since_start;      /* 启动以来总事件数 */
    uint64_t bytes_captured;          /* 捕获字节数估算 */
    time_t start_time;                /* 启动时间 */
    time_t last_event_time;           /* 最新事件时间 */
} StatsSnapshot;

/** @brief
 *
 * 内部速率追踪 (EMA)
 */
typedef struct {
    double rate_1min;                 /* EMA rate (events/sec) */
    double rate_5min;
    double rate_15min;
    uint64_t count;
    time_t window_start;
    time_t last_event_ts;
    pthread_mutex_t lock;
} RateTracker;

/**
 * @brief 初始化速率追踪器
 */
int stats_init(RateTracker *rt);

/**
 * @brief 记录一个新事件 — 更新 EMA
 */
void stats_record(RateTracker *rt, uint64_t bytes);

/**
 * @brief 获取当前统计快照
 */
void stats_get_snapshot(const RateTracker *rt, uint64_t total_events, StatsSnapshot *out);

/**
 * @brief 关闭统计模块
 */
void stats_shutdown(RateTracker *rt);

#endif
