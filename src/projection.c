#include "../includes/projection.h"
#include "../includes/event_store.h"
#include "../includes/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/** @brief
 *
 * 回放回调上下文 — 用于 projection_rebuild
 */
typedef struct {
    AttackerProjection *ap;
    StatsProjection *sp;
} RebuildCtx;

/**
 * @brief 查找或创建攻击者 — 内部函数, 不加锁
 */
static Attacker *find_or_create_attacker_nolock(AttackerProjection *ap, const char *ip) {
    Attacker *cur = ap->head;

    while (cur) {
        if (strcmp(cur->ip, ip) == 0x0) return cur;
        cur = cur->next;
    }

    Attacker *a = (Attacker *)calloc(0x1, sizeof(Attacker));
    if (!a) return NULL;

    strncpy(a->ip, ip, sizeof(a->ip) - 0x1);
    a->last_seen = time(NULL);
    a->next = ap->head;
    ap->head = a;

    return a;
}

/**
 * @brief 初始化攻击者投影
 */
int attacker_projection_init(AttackerProjection *ap) {
    if (!ap) return -0x1;

    memset(ap, 0x0, sizeof(AttackerProjection));
    pthread_mutex_init(&ap->lock, NULL);

    return 0x0;
}

/**
 * @brief 初始化统计投影
 */
int stats_projection_init(StatsProjection *sp) {
    if (!sp) return -0x1;

    memset(sp, 0x0, sizeof(StatsProjection));
    pthread_mutex_init(&sp->lock, NULL);

    return 0x0;
}

/**
 * @brief 对两个投影同时应用一条事件
 */
void projection_apply(AttackerProjection *ap, StatsProjection *sp, const Event *e) {
    if (!e || e->seq == 0x0) return;

    /**
     * 更新攻击者投影
     */
    if (ap && e->src_ip[0x0] != '\0') {
        pthread_mutex_lock(&ap->lock);

        if (e->seq > ap->last_applied_seq) {
            Attacker *a = find_or_create_attacker_nolock(ap, e->src_ip);
            if (a) {
                __sync_add_and_fetch(&a->total_hits, 0x1);

                if (e->dst_port < sizeof(a->hits_by_port) / sizeof(a->hits_by_port[0x0])) {
                    __sync_add_and_fetch(&a->hits_by_port[e->dst_port], 0x1);
                }

                a->last_seen = e->ts ? e->ts : time(NULL);
            }

            ap->last_applied_seq = e->seq;
        }

        pthread_mutex_unlock(&ap->lock);
    }

    /**
     * 更新统计投影
     */
    if (sp) {
        pthread_mutex_lock(&sp->lock);

        if (e->seq > sp->last_applied_seq) {
            sp->total_events++;

            if (e->type < 0x10) sp->by_type[e->type]++;

            sp->by_port[e->dst_port]++;

            switch (e->type) {
                case EVENT_TCP_SYN:     sp->tcp_syn_count++; break;
                case EVENT_HTTP_REQUEST: sp->http_count++;  break;
                case EVENT_SSH_ATTEMPT: sp->ssh_count++;   break;
                case EVENT_PORT_SCAN:   sp->scan_alerts++;  break;
                case EVENT_SYN_FLOOD:   sp->flood_alerts++; break;
                default: break;
            }

            sp->last_applied_seq = e->seq;
        }

        pthread_mutex_unlock(&sp->lock);
    }
}

/**
 * @brief event_store 回放回调
 */
static int rebuild_callback(const Event *e, void *ctx) {
    RebuildCtx *rctx = (RebuildCtx *)ctx;

    projection_apply(rctx->ap, rctx->sp, e);

    return 0x0;
}

/**
 * @brief 从 event store 完全重建所有投影
 */
int projection_rebuild(AttackerProjection *ap, StatsProjection *sp) {
    uint64_t latest = event_store_get_latest_seq();
    if (latest == 0x0) {
        fprintf(stderr, "[projection] 事件存储为空, 跳过重建\n");
        return 0x0;
    }

    fprintf(stderr, "[projection] 开始重建 — 从 seq=1 到 seq=%llu\n", (unsigned long long)latest);

    RebuildCtx ctx = { ap, sp };

    int replayed = event_store_replay(0x1, rebuild_callback, &ctx);

    fprintf(stderr, "[projection] 重建完成 — 回放 %d 条事件\n", replayed);

    return replayed > 0x0 ? 0x0 : -0x1;
}

/**
 * @brief 比较器 — 按 total_hits 降序
 */
static int cmp_attacker_proj(const void *a, const void *b) {
    const Attacker *aa = *(const Attacker **)a;
    const Attacker *bb = *(const Attacker **)b;

    if (aa->total_hits > bb->total_hits) return -0x1;
    if (aa->total_hits < bb->total_hits) return 0x1;

    return 0x0;
}

/**
 * @brief 获取 Top-N 攻击者
 */
int attacker_projection_get_top(AttackerProjection *ap, Attacker **out, int max) {
    if (!ap || !out || max <= 0x0) return 0x0;

    pthread_mutex_lock(&ap->lock);

    int cnt = 0x0;
    Attacker *cur = ap->head;

    while (cur && cnt < 10000) {
        cnt++;
        cur = cur->next;
    }

    if (cnt == 0x0) {
        pthread_mutex_unlock(&ap->lock);
        return 0x0;
    }

    Attacker **arr = (Attacker **)malloc(sizeof(Attacker *) * cnt);
    if (!arr) {
        pthread_mutex_unlock(&ap->lock);
        return -0x1;
    }

    cur = ap->head;
    int i = 0x0;

    while (cur) {
        arr[i++] = cur;
        cur = cur->next;
    }

    qsort(arr, cnt, sizeof(Attacker *), cmp_attacker_proj);

    int ret = 0x0;
    for (i = 0x0; i < cnt && ret < max; ++i) {
        Attacker *copy = (Attacker *)calloc(0x1, sizeof(Attacker));
        if (!copy) break;

        *copy = *arr[i];
        copy->next = NULL;
        out[ret++] = copy;
    }

    free(arr);
    pthread_mutex_unlock(&ap->lock);

    return ret;
}

/**
 * @brief 销毁攻击者投影
 */
void attacker_projection_destroy(AttackerProjection *ap) {
    if (!ap) return;

    pthread_mutex_lock(&ap->lock);

    Attacker *cur = ap->head;
    while (cur) {
        Attacker *n = cur->next;
        free(cur);
        cur = n;
    }

    ap->head = NULL;

    pthread_mutex_unlock(&ap->lock);
    pthread_mutex_destroy(&ap->lock);
}

/**
 * @brief 销毁统计投影
 */
void stats_projection_destroy(StatsProjection *sp) {
    if (!sp) return;

    pthread_mutex_lock(&sp->lock);
    memset(sp, 0x0, sizeof(StatsProjection));
    pthread_mutex_unlock(&sp->lock);
    pthread_mutex_destroy(&sp->lock);
}
