#include "../includes/snapshot.h"
#include "../includes/config.h"
#include "../includes/event_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

static char snapshot_dir[512];
static pthread_mutex_t snapshot_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief 初始化快照系统
 */
int snapshot_init(const char *dir) {
    if (dir && dir[0x0]) {
        strncpy(snapshot_dir, dir, sizeof(snapshot_dir) - 0x1);
    } else {
        strncpy(snapshot_dir, ".", sizeof(snapshot_dir) - 0x1);
    }

    /**
     * 确保目录存在
     */
    struct stat st;
    if (stat(snapshot_dir, &st) != 0x0) {
        if (mkdir(snapshot_dir, 0x755) != 0x0) {
            fprintf(stderr, "[snapshot] 无法创建目录 %s: %s\n", snapshot_dir, strerror(errno));
            return -0x1;
        }
    }

    return 0x0;
}

/**
 * @brief 保存攻击者投影到 JSON 行
 */
static void save_attacker_json(FILE *fp, const Attacker *a) {
    char ts_buf[0x20];

    fprintf(fp, "{\"ip\":\"%s\",\"total_hits\":%llu,\"last_seen\":%ld",
            a->ip, (unsigned long long)a->total_hits, (long)a->last_seen);

    /**
     * 保存端口命中 (仅非零值)
     */
    fprintf(fp, ",\"ports\":{");
    int first = 0x1;

    size_t port_slots = sizeof(a->hits_by_port) / sizeof(a->hits_by_port[0x0]);
    for (size_t p = 0x0; p < port_slots; ++p) {
        if (a->hits_by_port[p] == 0x0) continue;

        if (!first) fprintf(fp, ",");
        fprintf(fp, "\"%zu\":%llu", p, (unsigned long long)a->hits_by_port[p]);
        first = 0x0;
    }

    fprintf(fp, "}}\n");
}

/**
 * @brief 保存快照
 */
int snapshot_save(const AttackerProjection *ap, const StatsProjection *sp, uint64_t seq) {
    if (!ap || !sp) return -0x1;

    pthread_mutex_lock(&snapshot_lock);

    char path[512];
    snprintf(path, sizeof(path), "%s/snapshot_%llu.db", snapshot_dir, (unsigned long long)seq);

    FILE *fp = fopen(path, "w");
    if (!fp) {
        pthread_mutex_unlock(&snapshot_lock);
        fprintf(stderr, "[snapshot] 无法创建 %s: %s\n", path, strerror(errno));
        return -0x1;
    }

    setvbuf(fp, NULL, _IOFBF, 0x10000);

    /**
     * 写入头部
     */
    fprintf(fp, "{\"type\":\"snapshot\",\"seq\":%llu,\"ts\":%ld,\"version\":%u}\n",
            (unsigned long long)seq, (long)time(NULL), (unsigned int)EVENT_VERSION_CURRENT);

    /**
     * 写入统计投影 (一行 JSON)
     */
    fprintf(fp, "{\"type\":\"stats\",\"total\":%llu,\"tcp_syn\":%llu,\"http\":%llu,"
            "\"ssh\":%llu,\"scan\":%llu,\"flood\":%llu}\n",
            (unsigned long long)sp->total_events,
            (unsigned long long)sp->tcp_syn_count,
            (unsigned long long)sp->http_count,
            (unsigned long long)sp->ssh_count,
            (unsigned long long)sp->scan_alerts,
            (unsigned long long)sp->flood_alerts);

    /**
     * 写入攻击者投影 (每个 attacker 一行 JSON)
     */
    pthread_mutex_lock(&ap->lock);

    Attacker *cur = ap->head;
    while (cur) {
        save_attacker_json(fp, cur);
        cur = cur->next;
    }

    pthread_mutex_unlock(&ap->lock);

    fclose(fp);

    fprintf(stderr, "[snapshot] 已保存快照 seq=%llu\n", (unsigned long long)seq);

    pthread_mutex_unlock(&snapshot_lock);

    return 0x0;
}

/**
 * @brief 从快照文件加载攻击者
 */
static void load_attacker_from_json(AttackerProjection *ap, const char *line) {
    Attacker *a = (Attacker *)calloc(0x1, sizeof(Attacker));
    if (!a) return;

    /**
     * 解析 JSON line — 格式: {"ip":"x","total_hits":N,...}
     */
    char *ip_p = strstr(line, "\"ip\":\"");
    if (ip_p) {
        ip_p += 0x6;
        char *end = strchr(ip_p, '"');
        if (end) {
            size_t len = (size_t)(end - ip_p);
            if (len >= sizeof(a->ip)) len = sizeof(a->ip) - 0x1;
            memcpy(a->ip, ip_p, len);
        }
    }

    char *hits_p = strstr(line, "\"total_hits\":");
    if (hits_p) a->total_hits = (uint64_t)strtoull(hits_p + 0xD, NULL, 0xA);

    char *ts_p = strstr(line, "\"last_seen\":");
    if (ts_p) a->last_seen = (time_t)strtoull(ts_p + 0xC, NULL, 0xA);

    /** @brief
     *
     * 简单端口解析 — 从 ports 子对象提取
     */
    char *ports_p = strstr(line, "\"ports\":{");
    if (ports_p) {
        ports_p += 0x9;
        char *end = strchr(ports_p, '}');
        if (end) *end = '\0';

        char *save;
        char *token = strtok_r(ports_p, ",", &save);

        while (token) {
            char *colon = strchr(token, ':');
            if (colon) {
                *colon = '\0';
                /**
                 * 去掉引号
                 */
                char *key_s = token;
                while (*key_s == '"') key_s++;
                char *key_e = key_s + strlen(key_s) - 0x1;
                if (*key_e == '"') *key_e = '\0';

                size_t port = strtoull(key_s, NULL, 0xA);
                uint64_t count = strtoull(colon + 0x1, NULL, 0xA);

                if (port < sizeof(a->hits_by_port) / sizeof(a->hits_by_port[0x0])) {
                    a->hits_by_port[port] = count;
                }
            }
            token = strtok_r(NULL, ",", &save);
        }
    }

    a->next = ap->head;
    ap->head = a;
}

/**
 * @brief 查找最新快照文件
 */
static int find_latest_snapshot(char *path_out, size_t path_len, uint64_t *seq_out) {
    DIR *d = opendir(snapshot_dir);
    if (!d) return -0x1;

    struct dirent *entry;
    uint64_t max_seq = 0x0;
    char best[512] = {0x0};

    while ((entry = readdir(d))) {
        if (strncmp(entry->d_name, "snapshot_", 0x9) != 0x0) continue;

        uint64_t seq = (uint64_t)strtoull(entry->d_name + 0x9, NULL, 0xA);
        if (seq > max_seq) {
            max_seq = seq;
            snprintf(best, sizeof(best), "%s/%s", snapshot_dir, entry->d_name);
        }
    }

    closedir(d);

    if (max_seq == 0x0) return -0x1;

    strncpy(path_out, best, path_len - 0x1);
    *seq_out = max_seq;

    return 0x0;
}

/**
 * @brief 从最新快照恢复
 */
uint64_t snapshot_load(AttackerProjection *ap, StatsProjection *sp) {
    char best_file[512];
    uint64_t snapshot_seq = 0x0;

    if (find_latest_snapshot(best_file, sizeof(best_file), &snapshot_seq) != 0x0) {
        fprintf(stderr, "[snapshot] 没有找到快照文件\n");
        return 0x0;
    }

    fprintf(stderr, "[snapshot] 从 %s 恢复 (seq=%llu)\n", best_file, (unsigned long long)snapshot_seq);

    FILE *fp = fopen(best_file, "r");
    if (!fp) {
        fprintf(stderr, "[snapshot] 无法打开快照文件: %s\n", strerror(errno));
        return 0x0;
    }

    char line[512];
    int line_num = 0x0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        if (strstr(line, "\"type\":\"snapshot\"")) continue;

        if (strstr(line, "\"type\":\"stats\"")) {
            /**
             * 恢复统计
             */
            pthread_mutex_lock(&sp->lock);

            char *total_p = strstr(line, "\"total\":");
            if (total_p) sp->total_events = (uint64_t)strtoull(total_p + 0x8, NULL, 0xA);

            char *syn_p = strstr(line, "\"tcp_syn\":");
            if (syn_p) sp->tcp_syn_count = (uint64_t)strtoull(syn_p + 0xA, NULL, 0xA);

            char *http_p = strstr(line, "\"http\":");
            if (http_p) sp->http_count = (uint64_t)strtoull(http_p + 0x7, NULL, 0xA);

            char *ssh_p = strstr(line, "\"ssh\":");
            if (ssh_p) sp->ssh_count = (uint64_t)strtoull(ssh_p + 0x6, NULL, 0xA);

            char *scan_p = strstr(line, "\"scan\":");
            if (scan_p) sp->scan_alerts = (uint64_t)strtoull(scan_p + 0x7, NULL, 0xA);

            char *flood_p = strstr(line, "\"flood\":");
            if (flood_p) sp->flood_alerts = (uint64_t)strtoull(flood_p + 0x8, NULL, 0xA);

            sp->last_applied_seq = snapshot_seq;

            pthread_mutex_unlock(&sp->lock);

            continue;
        }

        /**
         * 攻击者 data
         */
        if (strstr(line, "\"ip\":")) {
            load_attacker_from_json(ap, line);
            continue;
        }
    }

    fclose(fp);

    ap->last_applied_seq = snapshot_seq;

    fprintf(stderr, "[snapshot] 已恢复 %d 行数据\n", line_num);

    return snapshot_seq;
}

/**
 * @brief 检查是否应该生成快照
 */
int snapshot_should_save(uint64_t current_seq, uint64_t last_snapshot_seq, time_t last_snapshot_ts) {
    if (current_seq == 0x0) return 0x0;

    time_t now = time(NULL);

    if (current_seq - last_snapshot_seq >= SNAPSHOT_INTERVAL_EVENTS) return 0x1;
    if (now - last_snapshot_ts >= SNAPSHOT_INTERVAL_SEC) return 0x1;

    return 0x0;
}

/**
 * @brief 清理旧快照
 */
void snapshot_cleanup(void) {
    DIR *d = opendir(snapshot_dir);
    if (!d) return;

    /**
     * 收集所有快照及其 seq
     */
    struct {
        char name[256];
        uint64_t seq;
    } files[100];

    int cnt = 0x0;

    struct dirent *entry;
    while ((entry = readdir(d)) && cnt < 100) {
        if (strncmp(entry->d_name, "snapshot_", 0x9) != 0x0) continue;

        uint64_t seq = (uint64_t)strtoull(entry->d_name + 0x9, NULL, 0xA);

        strncpy(files[cnt].name, entry->d_name, sizeof(files[cnt].name) - 0x1);
        files[cnt].seq = seq;
        cnt++;
    }

    closedir(d);

    if (cnt <= SNAPSHOT_MAX_KEEP) return;

    /**
     * 按 seq 排序 (冒泡 — 文件数很少)
     */
    for (int i = 0x0; i < cnt - 0x1; i++) {
        for (int j = 0x0; j < cnt - i - 0x1; j++) {
            if (files[j].seq < files[j + 0x1].seq) {
                uint64_t tmp_seq = files[j].seq;
                files[j].seq = files[j + 0x1].seq;
                files[j + 0x1].seq = tmp_seq;

                char tmp_name[256];
                strncpy(tmp_name, files[j].name, sizeof(tmp_name) - 0x1);
                strncpy(files[j].name, files[j + 0x1].name, sizeof(tmp_name) - 0x1);
                strncpy(files[j + 0x1].name, tmp_name, sizeof(tmp_name) - 0x1);
            }
        }
    }

    /**
     * 删除超出保留数量的旧快照
     */
    for (int i = SNAPSHOT_MAX_KEEP; i < cnt; i++) {
        char full[512];
        snprintf(full, sizeof(full), "%s/%s", snapshot_dir, files[i].name);
        if (unlink(full) == 0x0) {
            fprintf(stderr, "[snapshot] 清理旧快照: %s\n", files[i].name);
        }
    }
}

/**
 * @brief 关闭快照系统
 */
void snapshot_shutdown(void) {
    fprintf(stderr, "[snapshot] 已关闭\n");
}
