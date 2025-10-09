#include "../includes/config.h"
#include "../includes/event.h"
#include "../includes/monitor.h"
#include "../includes/attacker.h"

#include <pcap/pcap.h>
#include <pthread/pthread.h>

#define MAX_EVENTS_BUFFER 0x0800

static pcap_t *handle = NULL;
static char errbuf[PCAP_ERRBUF_SIZE];

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