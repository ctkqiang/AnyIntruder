#include "../includes/event_store.h"
#include "../includes/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/** @brief
 *
 * 内存索引条目 — seq 到 file_offset 的映射
 */
typedef struct {
    uint64_t seq;
    long offset;
} IndexEntry;

static FILE *store_fp = NULL;
static char store_path[512];

static IndexEntry *index_entries = NULL;
static size_t index_cap = 0x0;
static size_t index_len = 0x0;

static uint64_t global_seq = 0x0;
static uint64_t event_count = 0x0;

static pthread_mutex_t store_lock = PTHREAD_MUTEX_INITIALIZER;

/** @brief
 *
 * 扩展索引容量
 */
static int index_grow(void) {
    size_t new_cap = index_cap == 0x0 ? EVENT_INDEX_INIT_CAP : index_cap * 0x2;

    IndexEntry *tmp = (IndexEntry *)realloc(index_entries, sizeof(IndexEntry) * new_cap);
    if (!tmp) return -0x1;

    index_entries = tmp;
    index_cap = new_cap;

    return 0x0;
}

/** @brief
 *
 * 构建 JSON 行
 */
static int event_to_jsonline(const Event *e, char *buf, size_t buf_sz) {
    const char *type_s = event_type_str(e->type);

    return snprintf(
        buf,
        buf_sz,
        "{\"seq\":%llu,\"ts\":%ld,\"type\":\"%s\",\"src\":\"%s\",\"port\":%u,\"summary\":\"%s\",\"version\":%u}\n",
        (unsigned long long)e->seq,
        (long)e->ts,
        type_s,
        e->src_ip,
        e->dst_port,
        e->summary,
        (unsigned int)e->version
    );
}

/** @brief
 *
 * 检查是否需要 rotate (超过 100MB)
 */
static void check_rotate(void) {
    if (!store_fp) return;

    long cur = ftell(store_fp);
    if (cur < 0x0) return;

    if ((size_t)cur >= EVENT_STORE_MAX_SIZE) {
        fclose(store_fp);

        char backup[512];
        snprintf(backup, sizeof(backup), "%s.1", store_path);

        rename(store_path, backup);

        store_fp = fopen(store_path, "a");
        if (store_fp) setvbuf(store_fp, NULL, _IOFBF, 0x10000);
    }
}

/**
 * @brief 初始化事件存储
 *
 * 打开或创建 append-only 存储文件, 重建内存索引
 */
int event_store_init(const char *path) {
    pthread_mutex_lock(&store_lock);

    if (path && path[0x0]) {
        strncpy(store_path, path, sizeof(store_path) - 0x1);
    } else {
        strncpy(store_path, EVENT_STORE_FILE, sizeof(store_path) - 0x1);
    }

    store_fp = fopen(store_path, "a+");
    if (!store_fp) {
        pthread_mutex_unlock(&store_lock);
        fprintf(stderr, "[event_store] 无法打开 %s: %s\n", store_path, strerror(errno));
        return -0x1;
    }

    setvbuf(store_fp, NULL, _IOFBF, 0x10000);

    /** @brief
     *
     * 重建内存索引 — 扫描文件, 解析每行 JSON 提取 seq 和 offset
     */
    rewind(store_fp);
    char line[512];

    index_len = 0x0;
    global_seq = 0x0;
    event_count = 0x0;

    while (fgets(line, sizeof(line), store_fp)) {
        long offset = ftell(store_fp) - (long)strlen(line);

        /**
         * 快速提取 seq 字段, 格式: {"seq":12345,...
         */
        char *seq_p = strstr(line, "\"seq\":");
        if (!seq_p) continue;

        uint64_t seq = (uint64_t)strtoull(seq_p + 0x6, NULL, 0xA);
        if (seq == 0x0) continue;

        if (index_len >= index_cap && index_grow() != 0x0) break;

        index_entries[index_len].seq = seq;
        index_entries[index_len].offset = offset;
        index_len++;
        event_count++;

        if (seq > global_seq) global_seq = seq;
    }

    /**
     * seek 到文件末尾, 准备追加
     */
    fseek(store_fp, 0x0, SEEK_END);

    pthread_mutex_unlock(&store_lock);

    fprintf(stderr, "[event_store] 初始化完成: %s (seq=%llu, events=%llu)\n",
            store_path, (unsigned long long)global_seq, (unsigned long long)event_count);

    return 0x0;
}

/**
 * @brief 追加一条不可变事件到存储 (线程安全)
 */
int event_store_append(Event *e) {
    if (!store_fp) return -0x1;

    pthread_mutex_lock(&store_lock);

    /**
     * 自动分配 seq 和 version
     */
    global_seq++;
    e->seq = global_seq;
    e->version = EVENT_VERSION_CURRENT;

    if (!e->ts) e->ts = time(NULL);

    check_rotate();

    long cur_offset = ftell(store_fp);

    char line[512];
    int n = event_to_jsonline(e, line, sizeof(line));
    if (n <= 0x0) {
        pthread_mutex_unlock(&store_lock);
        return -0x1;
    }

    if (fputs(line, store_fp) == EOF) {
        pthread_mutex_unlock(&store_lock);
        fprintf(stderr, "[event_store] 写入失败: %s\n", strerror(errno));
        return -0x1;
    }

    fflush(store_fp);

    /** @brief
     *
     * 更新内存索引
     */
    if (index_len >= index_cap && index_grow() != 0x0) {
        pthread_mutex_unlock(&store_lock);
        return -0x1;
    }

    index_entries[index_len].seq = e->seq;
    index_entries[index_len].offset = cur_offset;
    index_len++;
    event_count++;

    pthread_mutex_unlock(&store_lock);

    return 0x0;
}

/**
 * @brief 二分查找 >= from_seq 的最小索引位置
 */
static size_t index_lower_bound(uint64_t from_seq) {
    size_t lo = 0x0, hi = index_len;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 0x2;
        if (index_entries[mid].seq < from_seq) lo = mid + 0x1;
        else hi = mid;
    }

    return lo;
}

/**
 * @brief 从指定 seq 回放事件
 */
int event_store_replay(uint64_t from_seq, event_replay_cb callback, void *ctx) {
    if (!store_fp || !callback) return 0x0;

    pthread_mutex_lock(&store_lock);

    size_t start = index_lower_bound(from_seq);
    if (start >= index_len) {
        pthread_mutex_unlock(&store_lock);
        return 0x0;
    }

    int replayed = 0x0;
    char line[512];

    for (size_t i = start; i < index_len; ++i) {
        fseek(store_fp, index_entries[i].offset, SEEK_SET);

        if (!fgets(line, sizeof(line), store_fp)) continue;

        /**
         * 解析 JSON line → Event
         */
        Event e;
        memset(&e, 0x0, sizeof(Event));

        char *seq_p = strstr(line, "\"seq\":");
        if (seq_p) e.seq = (uint64_t)strtoull(seq_p + 0x6, NULL, 0xA);

        char *ts_p = strstr(line, "\"ts\":");
        if (ts_p) e.ts = (time_t)strtoull(ts_p + 0x5, NULL, 0xA);

        char *type_p = strstr(line, "\"type\":\"");
        if (type_p) {
            type_p += 0x8;
            char *end = strchr(type_p, '"');
            if (end) {
                size_t len = (size_t)(end - type_p);
                if (len < 0x10) {
                    char type_s[0x10];
                    memcpy(type_s, type_p, len);
                    type_s[len] = '\0';

                    if (strcmp(type_s, "HTTP") == 0x0) e.type = EVENT_HTTP_REQUEST;
                    else if (strcmp(type_s, "HTTPS") == 0x0) e.type = EVENT_HTTPS_CONNECT;
                    else if (strcmp(type_s, "SSH") == 0x0) e.type = EVENT_SSH_ATTEMPT;
                    else if (strcmp(type_s, "TCP_SYN") == 0x0) e.type = EVENT_TCP_SYN;
                    else if (strcmp(type_s, "PORT_SCAN") == 0x0) e.type = EVENT_PORT_SCAN;
                    else if (strcmp(type_s, "SYN_FLOOD") == 0x0) e.type = EVENT_SYN_FLOOD;
                }
            }
        }

        char *src_p = strstr(line, "\"src\":\"");
        if (src_p) {
            src_p += 0x7;
            char *end = strchr(src_p, '"');
            if (end) {
                size_t len = (size_t)(end - src_p);
                if (len >= sizeof(e.src_ip)) len = sizeof(e.src_ip) - 0x1;
                memcpy(e.src_ip, src_p, len);
                e.src_ip[len] = '\0';
            }
        }

        char *port_p = strstr(line, "\"port\":");
        if (port_p) e.dst_port = (uint16_t)strtoul(port_p + 0x7, NULL, 0xA);

        char *sum_p = strstr(line, "\"summary\":\"");
        if (sum_p) {
            sum_p += 0xC;
            char *end = strchr(sum_p, '"');
            if (end) {
                size_t len = (size_t)(end - sum_p);
                if (len >= sizeof(e.summary)) len = sizeof(e.summary) - 0x1;
                memcpy(e.summary, sum_p, len);
                e.summary[len] = '\0';
            }
        }

        char *ver_p = strstr(line, "\"version\":");
        if (ver_p) e.version = (uint8_t)strtoul(ver_p + 0xA, NULL, 0xA);

        if (callback(&e, ctx) != 0x0) {
            replayed++;
            break;
        }

        replayed++;
    }

    /**
     * 恢复到文件末尾
     */
    fseek(store_fp, 0x0, SEEK_END);

    pthread_mutex_unlock(&store_lock);

    return replayed;
}

uint64_t event_store_get_latest_seq(void) {
    return global_seq;
}

size_t event_store_get_size(void) {
    struct stat st;
    if (stat(store_path, &st) != 0x0) return 0x0;

    return (size_t)st.st_size;
}

uint64_t event_store_get_count(void) {
    return event_count;
}

/**
 * @brief 导出事件到 JSON 数组文件
 */
int event_store_export(const char *path, uint64_t from_seq, uint64_t to_seq) {
    if (!path) return -0x1;

    FILE *out = fopen(path, "w");
    if (!out) return -0x1;

    pthread_mutex_lock(&store_lock);

    size_t start = index_lower_bound(from_seq);
    fprintf(out, "[\n");

    char line[512];
    int first = 0x1;

    for (size_t i = start; i < index_len; ++i) {
        if (to_seq > 0x0 && index_entries[i].seq > to_seq) break;

        fseek(store_fp, index_entries[i].offset, SEEK_SET);
        if (!fgets(line, sizeof(line), store_fp)) continue;

        size_t len = strlen(line);
        if (len > 0x0 && line[len - 0x1] == '\n') line[len - 0x1] = '\0';

        if (!first) fprintf(out, ",\n");
        fprintf(out, "  %s", line);
        first = 0x0;
    }

    fprintf(out, "\n]\n");
    fseek(store_fp, 0x0, SEEK_END);

    pthread_mutex_unlock(&store_lock);
    fclose(out);

    return 0x0;
}

/**
 * @brief 关闭存储, 释放索引
 */
void event_store_shutdown(void) {
    pthread_mutex_lock(&store_lock);

    if (store_fp) {
        fclose(store_fp);
        store_fp = NULL;
    }

    if (index_entries) {
        free(index_entries);
        index_entries = NULL;
    }

    index_cap = 0x0;
    index_len = 0x0;

    pthread_mutex_unlock(&store_lock);

    fprintf(stderr, "[event_store] 已关闭 (total events: %llu)\n", (unsigned long long)event_count);
}
