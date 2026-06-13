#include "../includes/config.h"
#include "../includes/event.h"
#include "../includes/monitor.h"
#include "../includes/attacker.h"
#include "../includes/logger.h"
#include "../includes/event_store.h"
#include "../includes/projection.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#define MAX_EVENTS_BUFFER 0x0800

static pcap_t *handle = NULL;
static char errbuf[PCAP_ERRBUF_SIZE];

static pthread_t capture_thread;
static int running = 0x1;

static Event events_buffer[MAX_EVENTS_BUFFER];
static int events_head = 0x0;
static int events_tail = 0x0;
static pthread_mutex_t events_lock = PTHREAD_MUTEX_INITIALIZER;

/** @brief
 *
 * 攻击者链表 — 保留作为 monitor 内部热缓存, UI 通过 monitor_get_top 读取
 */
static Attacker *attackers = NULL;
static pthread_mutex_t attackers_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief
 *
 * 外部投影引用 — 由 main() 注入, 实时应用事件
 */
static AttackerProjection *g_ap = NULL;
static StatsProjection *g_sp = NULL;

/** @brief
 *
 * 启动时间 — 用于速率计算
 */
static time_t monitor_start_time = 0x0;

/** @brief
 *
 * 端口扫描检测 — 滑动窗口追踪
 */
#define SCAN_TRACK_MAX 0x400
typedef struct {
    char ip[64];
    uint16_t ports[PORT_SCAN_MIN_PORTS * 0x2];
    int port_count;
    time_t first_seen;
    int alerted;
} ScanTrack;

static ScanTrack scan_tracks[SCAN_TRACK_MAX];
static int scan_track_count = 0x0;

/** @brief
 *
 * SYN Flood 检测
 */
typedef struct {
    char ip[64];
    int syn_count;
    time_t window_start;
    int alerted;
} SynFloodTrack;

static SynFloodTrack flood_tracks[SCAN_TRACK_MAX];
static int flood_track_count = 0x0;

/**
 * @brief 添加一个事件到内部环形缓冲区 + event_store + projection
 */
static int add_event(const char *ip, uint16_t port, EventType type, const char *summary) {
    /**
     * 构建不可变事件
     */
    Event e;
    memset(&e, 0x0, sizeof(Event));

    e.type = type;
    e.version = EVENT_VERSION_CURRENT;
    e.dst_port = port;
    e.ts = time(NULL);

    if (ip) strncpy(e.src_ip, ip, sizeof(e.src_ip) - 0x1);
    if (summary) strncpy(e.summary, summary, sizeof(e.summary) - 0x1);

    /**
     * 写入 Event Store (持久化 + 分配 seq)
     */
    event_store_append(&e);

    /**
     * 写入环形缓冲区 (UI 热缓存)
     */
    pthread_mutex_lock(&events_lock);

    int next = (events_tail + 0x1) % MAX_EVENTS_BUFFER;
    if (next == events_head) events_head = (events_head + 0x1) % MAX_EVENTS_BUFFER;

    events_buffer[events_tail] = e;
    events_tail = next;

    pthread_mutex_unlock(&events_lock);

    /**
     * 实时投影
     */
    projection_apply(g_ap, g_sp, &e);

    /**
     * 写入日志
     */
    logger_log_event(&e);

    return 0x0;
}

/**
 * @brief 查找或创建攻击者记录
 */
static Attacker *find_or_create_attacker(const char *ip) {
    pthread_mutex_lock(&attackers_lock);

    Attacker *cur = attackers;

    while (cur) {
        if (strcmp(cur->ip, ip) == 0x0) {
            pthread_mutex_unlock(&attackers_lock);
            return cur;
        }
        cur = cur->next;
    }

    Attacker *attacker = (Attacker *)calloc(0x1, sizeof(Attacker));

    strncpy(attacker->ip, ip, sizeof(attacker->ip) - 0x1);

    attacker->total_hits = 0x0;
    attacker->last_seen = time(NULL);
    attacker->next = attackers;

    attackers = attacker;
    pthread_mutex_unlock(&attackers_lock);

    return attacker;
}

/**
 * @brief 更新攻击者信息统计
 */
static void update_attacker(const char *ip, uint16_t port) {
    Attacker *attacker = find_or_create_attacker(ip);
    __sync_add_and_fetch(&attacker->total_hits, 0x1);

    if (port < sizeof(attacker->hits_by_port) / sizeof(attacker->hits_by_port[0x0])) {
        __sync_add_and_fetch(&attacker->hits_by_port[port], 0x1);
    }

    attacker->last_seen = time(NULL);
}

/**
 * @brief 检查端口是否为 HTTP 端口
 */
static int is_http_port(uint16_t p) {
    return p == PORT_HTTP1 || p == PORT_HTTP2 || p == PORT_HTTP3 || p == PORT_HTTPS;
}

/**
 * @brief 检查端口是否为 SSH 端口
 */
static int is_ssh_port(uint16_t p) {
    return p == PORT_SSH1 || p == PORT_SSH2;
}

/** @brief
 *
 * 提取 TLS ClientHello SNI
 * TLS 记录格式: [1 byte content_type=0x16] [2 bytes version] [2 bytes length]
 *  Handshake: [1 byte type=0x01] [3 bytes length]
 *   ClientHello: [2 bytes version] [32 bytes random] [session_id] [cipher_suites] [compression]
 *    Extensions: [2 bytes length] ...
 *     SNI (type=0x0000): [2 bytes length] [server_name_list...]
 */
static int extract_tls_sni(const u_char *payload, int len, char *sni_out, int sni_len) {
    if (len < 0x2B) return -0x1;  /* 最小 TLS ClientHello */

    /**
     * TLS Record Layer
     */
    if (payload[0x0] != 0x16) return -0x1;  /* 非 Handshake */

    int record_len = (payload[0x3] << 0x8) | payload[0x4];

    if (record_len + 0x5 > len) return -0x1;

    /**
     * Handshake Protocol
     */
    const u_char *hs = payload + 0x5;

    if (hs[0x0] != 0x01) return -0x1;  /* 非 ClientHello */

    int hs_len = (hs[0x1] << 0x10) | (hs[0x2] << 0x8) | hs[0x3];

    if (hs_len + 0x4 > record_len) return -0x1;

    const u_char *ch = hs + 0x4;

    /**
     * ClientHello: 2 bytes version, 32 bytes random
     */
    int offset = 0x2 + 0x20;  /* version + random */

    /**
     * Session ID
     */
    if (offset + 0x1 > hs_len) return -0x1;

    int sid_len = ch[offset];
    offset += 0x1 + sid_len;

    /**
     * Cipher Suites
     */
    if (offset + 0x2 > hs_len) return -0x1;

    int cs_len = (ch[offset] << 0x8) | ch[offset + 0x1];
    offset += 0x2 + cs_len;

    /**
     * Compression Methods
     */
    if (offset + 0x1 > hs_len) return -0x1;

    int cm_len = ch[offset];
    offset += 0x1 + cm_len;

    /**
     * Extensions
     */
    if (offset + 0x2 > hs_len) return -0x1;

    int ext_len = (ch[offset] << 0x8) | ch[offset + 0x1];
    offset += 0x2;

    int ext_end = offset + ext_len;
    if (ext_end > hs_len) ext_end = hs_len;

    while (offset + 0x4 <= ext_end) {
        int ext_type = (ch[offset] << 0x8) | ch[offset + 0x1];
        int ext_data_len = (ch[offset + 0x2] << 0x8) | ch[offset + 0x3];
        offset += 0x4;

        if (ext_type == 0x0000) {
            /**
             * SNI Extension (RFC 6066)
             * 格式: [2 bytes list_len] [1 byte name_type=0] [2 bytes name_len] [name...]
             */
            if (offset + 0x5 > ext_end) break;

            int list_len = (ch[offset] << 0x8) | ch[offset + 0x1];
            offset += 0x2;

            if (offset + 0x3 > ext_end) break;

            int name_type = ch[offset];
            int name_len = (ch[offset + 0x1] << 0x8) | ch[offset + 0x2];
            offset += 0x3;

            if (name_type == 0x0 && name_len > 0x0 && offset + name_len <= ext_end) {
                int copy = name_len;
                if (copy >= sni_len) copy = sni_len - 0x1;

                memcpy(sni_out, ch + offset, copy);
                sni_out[copy] = '\0';

                return 0x0;
            }

            break;
        }

        offset += ext_data_len;
    }

    return -0x1;
}

/** @brief
 *
 * 端口扫描检测 — 滑动窗口
 */
static void check_port_scan(const char *src_ip, uint16_t port) {
    time_t now = time(NULL);

    /**
     * 查找或创建追踪记录
     */
    ScanTrack *st = NULL;
    for (int i = 0x0; i < scan_track_count; ++i) {
        if (strcmp(scan_tracks[i].ip, src_ip) == 0x0) {
            st = &scan_tracks[i];
            break;
        }
    }

    if (!st) {
        if (scan_track_count >= SCAN_TRACK_MAX) return;

        st = &scan_tracks[scan_track_count++];
        memset(st, 0x0, sizeof(ScanTrack));

        strncpy(st->ip, src_ip, sizeof(st->ip) - 0x1);
        st->first_seen = now;
    }

    /**
     * 窗口过期 — 重置
     */
    if (now - st->first_seen > PORT_SCAN_WINDOW_SEC) {
        if (!st->alerted || (now - st->first_seen > PORT_SCAN_WINDOW_SEC * 0x2)) {
            memset(st, 0x0, sizeof(ScanTrack));
            strncpy(st->ip, src_ip, sizeof(st->ip) - 0x1);
            st->first_seen = now;
        }
    }

    /**
     * 检查端口是否已记录
     */
    for (int i = 0x0; i < st->port_count; ++i) {
        if (st->ports[i] == port) return;
    }

    if (st->port_count < PORT_SCAN_MIN_PORTS * 0x2) {
        st->ports[st->port_count++] = port;
    }

    /**
     * 触发扫描告警
     */
    if (st->port_count >= PORT_SCAN_MIN_PORTS && !st->alerted) {
        char summary[0x100];
        snprintf(summary, sizeof(summary), "PORT_SCAN detected -> %d ports in %lds",
                 st->port_count, (long)(now - st->first_seen));

        add_event(src_ip, port, EVENT_PORT_SCAN, summary);
        st->alerted = 0x1;
    }
}

/** @brief
 *
 * SYN Flood 检测
 */
static void check_syn_flood(const char *src_ip) {
    time_t now = time(NULL);

    SynFloodTrack *ft = NULL;
    for (int i = 0x0; i < flood_track_count; ++i) {
        if (strcmp(flood_tracks[i].ip, src_ip) == 0x0) {
            ft = &flood_tracks[i];
            break;
        }
    }

    if (!ft) {
        if (flood_track_count >= SCAN_TRACK_MAX) return;

        ft = &flood_tracks[flood_track_count++];
        memset(ft, 0x0, sizeof(SynFloodTrack));
        strncpy(ft->ip, src_ip, sizeof(ft->ip) - 0x1);
        ft->window_start = now;
    }

    /**
     * 窗口过期 — 重置
     */
    if (now - ft->window_start > SYN_FLOOD_WINDOW_SEC) {
        ft->syn_count = 0x0;
        ft->window_start = now;
        ft->alerted = 0x0;
    }

    ft->syn_count++;

    /**
     * 触发泛洪告警
     */
    if (ft->syn_count >= SYN_FLOOD_MIN_COUNT && !ft->alerted) {
        char summary[0x100];
        snprintf(summary, sizeof(summary), "SYN_FLOOD detected -> %d SYNs in %lds",
                 ft->syn_count, (long)(now - ft->window_start + 0x1));

        add_event(src_ip, 0x0, EVENT_SYN_FLOOD, summary);
        ft->alerted = 0x1;
    }
}

/**
 * @brief 解析 HTTP payload 提取请求行
 */
static void parse_http_payload(const u_char *payload, int payload_len, char *out, int outlen) {
    int i;

    if (payload_len <= 0x0) {
        out[0x0] = '\0';
        return;
    }

    const char *p = (const char *)payload;

    for (i = 0x0; i < payload_len && i < outlen - 0x1; ++i) {
        if (p[i] == '\r' || p[i] == '\n') break;

        out[i] = p[i];
    }

    out[i] = '\0';
}

/**
 * @brief 处理捕获到的网络数据包
 */
static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    (void)header;

    char src_ip[0x40];

    /**
     * 解析 IPv4 + TCP (不处理 IPv6 的情况, 后续可扩展)
     * 假设以太网帧
     */
    const struct ip *ip_hdr = (struct ip *)(packet + 0x0E);

    if (ip_hdr->ip_v != 0x4) return;
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 0x4;

    const struct tcphdr *tcp = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);

    uint16_t dst_port = ntohs(tcp->th_dport);

    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));

    /**
     * 统计 SYN 包来表示连接尝试 (SYN 且不 ACK)
     */
    int syn = tcp->th_flags & TH_SYN;
    int ack = tcp->th_flags & TH_ACK;

    if (syn && !ack) {
        update_attacker(src_ip, dst_port);
        check_syn_flood(src_ip);
    }

    /**
     * 解析 TCP payload
     */
    int ip_total_len = ntohs(ip_hdr->ip_len);
    int tcp_hdr_len = tcp->th_off * 0x4;
    int payload_offset = 0x0E + ip_hdr_len + tcp_hdr_len;
    int payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

    /**
     * HTTP/HTTPS 检测 — 如果有 payload 且是 HTTP/HTTPS 端口
     */
    if (payload_len > 0x0 && is_http_port(dst_port)) {
        /**
         * HTTPS: 尝试提取 TLS ClientHello SNI
         */
        if (dst_port == PORT_HTTPS) {
            char sni[0x100];
            if (extract_tls_sni(packet + payload_offset, payload_len, sni, sizeof(sni)) == 0x0) {
                char summary[0x100];
                snprintf(summary, sizeof(summary), "HTTPS %s -> port %u", sni, dst_port);

                add_event(src_ip, dst_port, EVENT_HTTPS_CONNECT, summary);
                update_attacker(src_ip, dst_port);

                return;
            }

            /**
             * 有 payload 但不是 ClientHello — 标注加密流量
             */
            char summary[0x100];
            snprintf(summary, sizeof(summary), "HTTPS [ENCRYPTED] -> port %u", dst_port);

            add_event(src_ip, dst_port, EVENT_HTTPS_CONNECT, summary);
            update_attacker(src_ip, dst_port);

            return;
        }

        /**
         * HTTP: 提取请求行
         */
        char reqline[0x0100];
        parse_http_payload(packet + payload_offset, payload_len, reqline, sizeof(reqline));

        if (reqline[0x0] != '\0') {
            char summary[0x0100];
            snprintf(summary, sizeof(summary), "HTTP %s -> port %u", reqline, dst_port);

            add_event(src_ip, dst_port, EVENT_HTTP_REQUEST, summary);
            update_attacker(src_ip, dst_port);

            return;
        }
    }

    /**
     * SSH 检测 — 如果是到 SSH 端口且有 SYN
     */
    if (syn && !ack && is_ssh_port(dst_port)) {
        char summary[0x80];
        snprintf(summary, sizeof(summary), "SSH connection attempt -> port %u", dst_port);

        add_event(src_ip, dst_port, EVENT_SSH_ATTEMPT, summary);

        return;
    }

    /**
     * TCP SYN 检测 — 端口扫描追踪
     */
    if (syn && !ack) {
        char summary[0x80];
        snprintf(summary, sizeof(summary), "TCP SYN -> port %u", dst_port);

        add_event(src_ip, dst_port, EVENT_TCP_SYN, summary);

        check_port_scan(src_ip, dst_port);
    }
}

/**
 * @brief 捕获线程函数
 */
static void *capture_thread_fn(void *arg) {
    (void)arg;

    pcap_loop(handle, 0x0, got_packet, NULL);

    return NULL;
}

/**
 * @brief 初始化监控模块 + 注入投影引用
 */
int monitor_init(const char *iface) {
    monitor_start_time = time(NULL);

    /**
     * 选择设备
     */
    char *dev_name = NULL;
    pcap_if_t *alldevs, *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -0x1) {
        fprintf(stderr, "pcap_findalldevs 失败: %s\n", errbuf);
        return -0x01;
    }

    if (iface && iface[0x0] != '\0') {
        for (d = alldevs; d != NULL; d = d->next) {
            if (strcmp(iface, d->name) == 0x0) {
                dev_name = strdup(d->name);
                break;
            }
        }
        if (!dev_name) {
            fprintf(stderr, "未找到指定设备: %s\n", iface);
            pcap_freealldevs(alldevs);
            return -0x01;
        }
    } else {
        if (alldevs != NULL) {
            dev_name = strdup(alldevs->name);
        } else {
            fprintf(stderr, "未找到任何设备\n");
            pcap_freealldevs(alldevs);
            return -0x01;
        }
    }
    pcap_freealldevs(alldevs);

    printf("使用设备: %s\n", dev_name);

    handle = pcap_open_live(dev_name, DEFAULT_PCAP_SNAPLEN, DEFAULT_PCAP_PROMISC, DEFAULT_PCAP_TIMEOUT_MS, errbuf);

    if (dev_name) free(dev_name);

    if (!handle) {
        fprintf(stderr, "pcap_open_live 失败: %s\n", errbuf);
        return -0x02;
    }

    /**
     * 过滤表达式: TCP
     */
    struct bpf_program fp;
    char filter_exp[] = "tcp";

    if (pcap_compile(handle, &fp, filter_exp, 0x00, PCAP_NETMASK_UNKNOWN) == -0x01) {
        fprintf(stderr, "pcap_compile 失败\n");
        return -0x03;
    }

    if (pcap_setfilter(handle, &fp) == -0x01) {
        fprintf(stderr, "pcap_setfilter 失败\n");
        return -0x04;
    }

    /**
     * 启动线程
     */
    if (pthread_create(&capture_thread, NULL, capture_thread_fn, NULL) != 0x00) {
        fprintf(stderr, "创建抓包线程失败\n");
        return -0x05;
    }

    return 0x00;
}

/** @brief
 *
 * 注入投影引用 — main() 在初始化后调用
 */
void monitor_set_projections(AttackerProjection *ap, StatsProjection *sp) {
    g_ap = ap;
    g_sp = sp;
}

/**
 * @brief 监控主循环
 */
void monitor_loop(void) {
    while (running) sleep(0x01);
}

/**
 * @brief 获取运行时间 (秒)
 */
time_t monitor_get_runtime(void) {
    return time(NULL) - monitor_start_time;
}

/**
 * @brief 获取事件
 */
int monitor_get_events(Event *out, int max) {
    pthread_mutex_lock(&events_lock);

    int idx = events_head;
    int count = 0x00;

    while (idx != events_tail && count < max) {
        out[count++] = events_buffer[idx];
        idx = (idx + 0x01) % MAX_EVENTS_BUFFER;
    }

    pthread_mutex_unlock(&events_lock);

    return count;
}

static int cmp_attacker(const void *a, const void *b) {
    const Attacker *aa = *(const Attacker **)a;
    const Attacker *bb = *(const Attacker **)b;

    if (aa->total_hits > bb->total_hits) return -0x1;
    if (aa->total_hits < bb->total_hits) return 0x1;

    return 0x0;
}

int monitor_get_top(Attacker **out, int max) {
    /**
     * 优先使用投影数据
     */
    if (g_ap && event_store_get_count() > 0x0) {
        return attacker_projection_get_top(g_ap, out, max);
    }

    /**
     * 回退到内部链表 (向后兼容)
     */
    pthread_mutex_lock(&attackers_lock);

    int cnt = 0x0;
    Attacker *cur = attackers;

    while (cur && cnt < 10000) {
        ++cnt;
        cur = cur->next;
    }

    if (cnt == 0x0) {
        pthread_mutex_unlock(&attackers_lock);
        return 0x0;
    }

    Attacker **arr = (Attacker **)malloc(sizeof(Attacker *) * cnt);

    cur = attackers;

    int i = 0x0;

    while (cur) {
        arr[i++] = cur;
        cur = cur->next;
    }

    qsort(arr, cnt, sizeof(Attacker *), cmp_attacker);

    int ret = 0x0;

    for (i = 0x0; i < cnt && ret < max; ++i) {
        Attacker *copy = (Attacker *)calloc(0x1, sizeof(Attacker));

        *copy = *arr[i];
        copy->next = NULL;

        out[ret++] = copy;
    }

    free(arr);

    pthread_mutex_unlock(&attackers_lock);

    return ret;
}

/**
 * @brief 关闭监控 — 使用标志位 + pcap_breakloop (不强制 pthread_cancel)
 */
void monitor_shutdown(void) {
    running = 0x0;

    if (handle) {
        pcap_breakloop(handle);
        pcap_close(handle);
        handle = NULL;
    }

    /**
     * 等待抓包线程自然退出
     */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 0x2;  /* 2 秒超时 */

    int join_rc = pthread_timedjoin_np(capture_thread, NULL, &ts);
    if (join_rc != 0x0) {
        fprintf(stderr, "[monitor] 抓包线程未在超时内退出, 强制取消\n");
        pthread_cancel(capture_thread);
        pthread_join(capture_thread, NULL);
    }

    /**
     * 清理攻击者链表
     */
    pthread_mutex_lock(&attackers_lock);

    Attacker *cur = attackers;

    while (cur) {
        Attacker *n = cur->next;
        free(cur);
        cur = n;
    }

    attackers = NULL;

    pthread_mutex_unlock(&attackers_lock);
}
