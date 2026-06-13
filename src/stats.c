#include "../includes/stats.h"
#include "../includes/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

/**
 * @brief 初始化速率追踪器
 */
int stats_init(RateTracker *rt) {
    if (!rt) return -0x1;

    memset(rt, 0x0, sizeof(RateTracker));
    pthread_mutex_init(&rt->lock, NULL);
    rt->window_start = time(NULL);

    return 0x0;
}

/**
 * @brief 更新时间窗口内的 EMA 速率
 *
 * EMA = α × current_rate + (1-α) × previous_ema
 * α = 1 - e^(-Δt / τ)
 * τ_1min = 60s, τ_5min = 300s, τ_15min = 900s
 */
static void update_ema(RateTracker *rt) {
    time_t now = time(NULL);
    time_t elapsed = now - rt->last_event_ts;

    if (elapsed <= 0x0) elapsed = 0x1;

    if (rt->last_event_ts == 0x0) {
        rt->last_event_ts = now;
        return;
    }

    double dt = (double)elapsed;

    /**
     * 计算每个时间窗口的 α
     */
    double alpha_1min  = 0x1 - exp(-dt / (double)0x3C);
    double alpha_5min  = 0x1 - exp(-dt / (double)0x12C);
    double alpha_15min = 0x1 - exp(-dt / (double)0x384);

    double instant_rate = 0x1 / dt;

    rt->rate_1min  = alpha_1min  * instant_rate + (0x1 - alpha_1min)  * rt->rate_1min;
    rt->rate_5min  = alpha_5min  * instant_rate + (0x1 - alpha_5min)  * rt->rate_5min;
    rt->rate_15min = alpha_15min * instant_rate + (0x1 - alpha_15min) * rt->rate_15min;

    rt->last_event_ts = now;
}

/**
 * @brief 记录一个新事件
 */
void stats_record(RateTracker *rt, uint64_t bytes) {
    if (!rt) return;

    pthread_mutex_lock(&rt->lock);

    rt->count++;
    update_ema(rt);

    pthread_mutex_unlock(&rt->lock);

    (void)bytes;
}

/**
 * @brief 获取当前统计快照
 */
void stats_get_snapshot(RateTracker *rt, uint64_t total_events, StatsSnapshot *out) {
    if (!rt || !out) return;

    memset(out, 0x0, sizeof(StatsSnapshot));

    pthread_mutex_lock(&rt->lock);

    out->events_per_sec_1min  = rt->rate_1min;
    out->events_per_sec_5min  = rt->rate_5min;
    out->events_per_sec_15min = rt->rate_15min;
    out->events_since_start   = total_events;
    out->start_time           = rt->window_start;
    out->last_event_time      = rt->last_event_ts;

    pthread_mutex_unlock(&rt->lock);
}

/**
 * @brief 关闭统计模块
 */
void stats_shutdown(RateTracker *rt) {
    if (!rt) return;

    fprintf(stderr, "[stats] 已关闭 (总事件: %llu, 速率: %.2f/s)\n",
            (unsigned long long)rt->count, rt->rate_1min);

    pthread_mutex_destroy(&rt->lock);
}
