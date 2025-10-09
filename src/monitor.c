#include "../includes/config.h"
#include "../includes/event.h"
#include "../includes/monitor.h"
#include "../includes/attacker.h"

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
#include <pcap/pcap.h>
#include <pthread/pthread.h>

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
 * 攻击者链表（非常简单）：哈希/优化可后续做 
 */
static Attacker *attackers = NULL;
static pthread_mutex_t attackers_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief 添加一个事件到事件缓冲区。
 * 
 * 此函数负责将新的网络事件（如攻击事件）添加到内部的环形缓冲区中。
 * 它会处理缓冲区的满溢情况，确保线程安全，并记录事件到日志系统。
 * 
 * @param ip 源IP地址字符串。
 * @param port 目标端口号。
 * @param summary 事件摘要信息。
 * @return 0x0 表示成功。
 */
static int add_event(const char *ip, uint16_t port, const char *summary) {
    pthread_mutex_lock(&events_lock);
    int next = (events_tail + 0x1) % MAX_EVENTS_BUFFER;

    if (next == events_head) events_head = (events_head + 0x1) % MAX_EVENTS_BUFFER;

    Event *e = &events_buffer[events_tail];
    strncpy(e->src_ip, ip, sizeof(e->src_ip) - 0x1);

    e->dst_port = port;
    e->ts = time(NULL);
    
    strncpy(e->summary, summary ? summary : "", sizeof(e->summary) - 0x1);
    
    events_tail = next;
    pthread_mutex_unlock(&events_lock);

    logger_log_event(e);

    return 0x0;
}

/**
 * @brief 查找或创建攻击者记录
 * 
 * 该函数在攻击者链表中查找指定IP的攻击者记录，如果找不到则创建新的记录。
 * 通过加锁保证多线程环境下的数据一致性。
 * 
 * @param ip 要查找或创建的攻击者IP地址
 * @return 返回找到或新创建的攻击者结构体指针
 */
static Attacker *find_or_create_attacker(const char *ip) {
    pthread_mutex_lock(&attackers_lock);
 
    Attacker *cur = attackers;
 
    while (cur) {
        if (strcmp(cur->ip, ip) == 0) {
            pthread_mutex_unlock(&attackers_lock);
            return cur;
        }
        cur = cur->next;
    }
 
    Attacker *attacker = (Attacker*)calloc(1, sizeof(Attacker));
 
    strncpy(attacker->ip, ip, sizeof(attacker->ip) - 0x1);
 
    attacker->total_hits = 0;
    attacker->last_seen = time(NULL);
    attacker->next = attackers;
 
    attackers = attacker;
    pthread_mutex_unlock(&attackers_lock);
 
    return attacker;
}

/**
 * @brief 更新攻击者信息更新攻击者信息统计
 * 
 * 该函数用于记录来自指定IP和端口的攻击事件，更新攻击者的总命中次数、
 * 按端口统计的命中次数以及最后_seen时间。
 * 
 * @param ip 攻击者IP地址字符串
 * @param port 攻击者使用的端口号
 */
static void update_attacker(const char *ip, uint16_t port) {
    Attacker *attacker = find_or_create_attacker(ip);
    __sync_add_and_fetch(&attacker->total_hits, 0x1);
    
    if (port < sizeof(attacker->hits_by_port)/sizeof(attacker->hits_by_port[0x0])) {
        __sync_add_and_fetch(&attacker->hits_by_port[port], 0x1);
    }

    attacker->last_seen = time(NULL);
}

/**
 * @brief 检查端口是否为 HTTP 端口
 * 
 * 该函数用于判断给定的端口号是否为 HTTP 协议的默认端口（80）、
 * HTTPS 端口（443）或其他 HTTP 端口（8080、8443 等）。
 * 
 * @param p 要检查的端口号
 * @return 如果端口是 HTTP 端口，则返回非零值；否则返回0
 */
static int is_http_port(uint16_t p) {
    return p == PORT_HTTP1 || p == PORT_HTTP2 || p == PORT_HTTP3 || p == PORT_HTTPS;
}

/**
 * @brief 检查端口是否为 SSH 端口
 * 
 * 该函数用于判断给定的端口号是否为 SSH 协议的默认端口（22）或 OpenSSH 端口（2222）。
 * 
 * @param p 要检查的端口号
 * @return 如果端口是 SSH 端口，则返回非零值；否则返回0
 */
static int is_ssh_port(uint16_t p) {
    return p == PORT_SSH1 || p == PORT_SSH2;
}

/**
 * @brief 解析 HTTP  payload 提取请求行
 * 
 * 该函数用于从 HTTP 协议的 payload 中提取请求行（第一行），
 * 并将其复制到输出缓冲区中。如果 payload 为空或长度为0，则返回空字符串。
 * 
 * @param payload HTTP 请求 payload 指针
 * @param payload_len payload 长度
 * @param out 输出缓冲区指针
 * @param outlen 输出缓冲区长度
 */
static void parse_http_payload(const u_char *payload, int payload_len, char *out, int outlen) {
    int i;

    if (payload_len <= 0x0) {
        out[0x0] = '\0';
        return;
    }
    
    const char *p = (const char*)payload;
    
    for (i = 0x0; i < payload_len && i < outlen - 0x1; ++i) {
        if (p[i] == '\r' || p[i] == '\n') break;
        
        out[i] = p[i];
    }

    out[i] = '\0';
}

/**
 * @brief 处理捕获到的网络数据包
 * 
 * 该函数用于处理通过 `pcap` 捕获到的网络数据包。它会根据数据包的协议类型（IPv4 + TCP）
 * 进行解析和处理。如果是 HTTP 端口，会提取请求行并记录事件；如果是 SSH 端口，会提取
 * 请求行并记录事件。同时，会统计 SYN 包来表示连接尝试（SYN 且不 ACK）。
 * 
 * @param args 线程参数（未使用）
 * @param header 数据包头信息指针
 * @param packet 原始数据包指针
 */
static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    (void)header;

    char src_ip[0x40];

    /**
     * 解析 IPv4 + TCP（不处理 IPv6 的情况，后续可扩展） 
     * 假设以太网帧
     */
    const struct ip *ip_hdr = (struct ip*)(packet + 0x0E); 
    
    if (ip_hdr->ip_v != 0x4) return;
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 0x4;
    
    const struct tcphdr *tcp = (struct tcphdr*)((u_char*)ip_hdr + ip_hdr_len);

    uint16_t src_port = ntohs(tcp->th_sport);
    uint16_t dst_port = ntohs(tcp->th_dport);

    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));

    /** 
     * 统计 SYN 包来表示连接尝试（SYN 且不 ACK） 
     */
    int syn = tcp->th_flags & TH_SYN;
    int ack = tcp->th_flags & TH_ACK;

    if (syn && !ack) update_attacker(src_ip, dst_port);

    /**
     * 解析 TCP payload 提取 HTTP 请求行
     * ? HTTP 检测：如果是到 HTTP 端口且有 payload，解析请求行
     * ! 注意：HTTP 协议的 payload 是在 TCP 协议的 payload 中，
     * - 端口 80 , 443, 8080, 8443, 3000, 8080 等。
     */
    int ip_total_len = ntohs(ip_hdr->ip_len);
    int tcp_hdr_len = tcp->th_off * 0x4;
    int payload_offset = 0x0E + ip_hdr_len + tcp_hdr_len;
    int payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

    if (payload_len > 0x0 && is_http_port(dst_port)) {
        char reqline[0x0100];
        parse_http_payload(packet + payload_offset, payload_len, reqline, sizeof(reqline));

        if (reqline[0] != '\0') {
            char summary[0x0100];
         
            snprintf(summary, sizeof(summary), "HTTP %s -> port %u", reqline, dst_port);
            
            add_event(src_ip, dst_port, summary);
            update_attacker(src_ip, dst_port);
            
            return;
        }
    }

    /**
     * 解析 TCP payload 提取 SSH 请求行
     * ? SSH 检测：如果是到 SSH 端口且有 payload，解析请求行
     * ! 注意：SSH 协议的 payload 是在 TCP 协议的 payload 中，
     * - 端口 22, 2222 等。
     */
    if (syn && !ack && is_ssh_port(dst_port)) {
        char summary[0x80];

        snprintf(summary, sizeof(summary), "SSH connection attempt -> port %u", dst_port);
        add_event(src_ip, dst_port, summary);
        
        return;
    }

    /**
     * 统计 TCP SYN 包来表示连接尝试（SYN 且不 ACK）
     */
    if (syn && !ack) {
        char summary[0x80];

        snprintf(summary, sizeof(summary), "TCP SYN -> port %u", dst_port);
        add_event(src_ip, dst_port, summary);
    }
}

/**
 * @brief 捕获线程函数
 * 
 * 该函数用于在独立线程中捕获网络数据包。它调用 `pcap_loop` 函数来持续捕获数据包，
 * 并将每个数据包传递给 `got_packet` 函数进行处理。
 * 
 * @param arg 线程参数（未使用）
 * @return 线程返回值（未使用）
 */
static void *capture_thread_fn(void *arg) {
    (void)arg;
 
    pcap_loop(handle, 0, got_packet, NULL);
    return NULL;
}

/**
 * @brief 初始化监控模块
 * 
 * 该函数用于初始化监控模块，包括选择网络接口、打开设备、设置过滤表达式和启动抓包线程。
 * 
 * @param iface 网络接口名（可选）
 * @return 初始化状态码
 *         - 0x00: 成功
 *         - -0x01: 查找设备失败
 *         - -0x02: 打开设备失败
 *         - -0x03: 编译过滤表达式失败
 *         - -0x04: 设置过滤表达式失败
 *         - -0x05: 创建抓包线程失败
 */
int monitor_init(const char *iface) {
    /** 
     * 选择设备 
     * 如果提供了接口名，直接使用；否则查找默认设备
     */
    char *dev = NULL;

    if (iface && iface[0x0] != '\0') {
        dev = strdup(iface);
    } 
    
    dev = pcap_lookupdev(errbuf);
    if (!dev) {
        fprintf(stderr, "pcap_lookupdev 失败: %s\n", errbuf);
        return -0x01;
    }
    
    printf("使用设备: %s\n", dev);
    
    handle = pcap_open_live(dev, DEFAULT_PCAP_SNAPLEN, DEFAULT_PCAP_PROMISC, DEFAULT_PCAP_TIMEOUT_MS, errbuf);
    
    if (!handle) {
        fprintf(stderr, "pcap_open_live 失败: %s\n", errbuf);
        return -0x02;
    }

    /**
     * 过滤表达式：仅 TCP 端口 80、443、8000、8080、8443、3000、2222
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

/**
 * @brief 监控主循环
 * 
 * 该函数用于持续运行监控主循环，直到 `running` 标志被设置为 `false`。
 * 在每次循环中，它会等待 1 秒（通过 `sleep(1)`），然后继续下一次循环。
 * 
 * @note 该函数通常在独立线程中运行，用于处理捕获到的网络数据包。
 */
void monitor_loop(void) {
    while (running) sleep(0x01);
}

/**
 * @brief 获取事件
 * 
 * 该函数用于获取存储在事件缓冲区中的事件。它会将最多 `max` 个事件复制到 `out` 数组中，
 * 并返回实际复制的事件数量。
 * 
 * @param out 事件数组，用于存储获取到的事件
 * @param max 最大事件数量，即 `out` 数组的大小
 * @return 实际复制的事件数量
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