#pragma once

#include <stdint.h>

#ifndef EVENT_H
#define EVENT_H

#include <time.h>

/** @brief
 *
 * 事件类型枚举 — 不可变事件分类
 */
typedef enum {
    EVENT_UNKNOWN           = 0x00,
    EVENT_TCP_SYN           = 0x01,
    EVENT_HTTP_REQUEST      = 0x02,
    EVENT_HTTPS_CONNECT     = 0x03,
    EVENT_SSH_ATTEMPT       = 0x04,
    EVENT_PORT_SCAN         = 0x05,
    EVENT_SYN_FLOOD         = 0x06,
    EVENT_DNS_QUERY         = 0x07,
    EVENT_ARP_SPOOF         = 0x08,
    EVENT_BRUTE_FORCE       = 0x09
} EventType;

/** @brief
 *
 * 事件版本 — 用于 schema 演进
 */
#define EVENT_VERSION_CURRENT 0x01

/** @brief
 *
 * 不可变事件 — Event Sourcing 核心单元
 * 所有字段一旦写入即不可变
 */
typedef struct Event {
    uint64_t seq;              /* 全局递增序列号 */
    EventType type;            /* 事件类型 */
    uint8_t version;           /* schema 版本 */
    char src_ip[64];           /* 来源 IP */
    uint16_t dst_port;         /* 目标端口 */
    char summary[256];         /* 可读摘要 */
    time_t ts;                 /* Unix 时间戳 */
} Event;

/** @brief
 *
 * 事件类型转可读字符串
 */
static inline const char *event_type_str(EventType t) {
    switch (t) {
        case EVENT_TCP_SYN:       return "TCP_SYN";
        case EVENT_HTTP_REQUEST:  return "HTTP";
        case EVENT_HTTPS_CONNECT: return "HTTPS";
        case EVENT_SSH_ATTEMPT:   return "SSH";
        case EVENT_PORT_SCAN:     return "PORT_SCAN";
        case EVENT_SYN_FLOOD:     return "SYN_FLOOD";
        case EVENT_DNS_QUERY:     return "DNS";
        case EVENT_ARP_SPOOF:     return "ARP_SPOOF";
        case EVENT_BRUTE_FORCE:   return "BRUTE_FORCE";
        default:                  return "UNKNOWN";
    }
}

#endif
