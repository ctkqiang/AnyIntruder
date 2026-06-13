#pragma once

#ifndef CONFIG_H
#define CONFIG_H

#define DEFAULT_PCAP_SNAPLEN 65535
#define DEFAULT_PCAP_PROMISC 1
#define DEFAULT_PCAP_TIMEOUT_MS 1000

#define LOG_FILE "anyintruder.log"
#define MAX_IP_STRLEN 64
#define MAX_EVENTS 1024
#define TOP_N 10

/** @brief
 *
 * 端口常量
 */
#define PORT_HTTP1 80
#define PORT_HTTP2 8000
#define PORT_HTTP3 8080
#define PORT_HTTPS 443
#define PORT_SSH1 22
#define PORT_SSH2 2222
#define PORT_DNS  53

/** @brief
 *
 * Event Store 常量
 */
#define EVENT_STORE_FILE        "events.db"
#define EVENT_STORE_MAX_SIZE_MB 100
#define EVENT_STORE_MAX_SIZE    (EVENT_STORE_MAX_SIZE_MB * 1024 * 1024)
#define EVENT_INDEX_INIT_CAP    8192

/** @brief
 *
 * Snapshot 常量
 */
#define SNAPSHOT_INTERVAL_EVENTS 5000
#define SNAPSHOT_INTERVAL_SEC    60
#define SNAPSHOT_MAX_KEEP        3

/** @brief
 *
 * 检测阈值
 */
#define PORT_SCAN_WINDOW_SEC   5
#define PORT_SCAN_MIN_PORTS    10
#define SYN_FLOOD_WINDOW_SEC   1
#define SYN_FLOOD_MIN_COUNT    100
#define BRUTE_FORCE_WINDOW_SEC 10
#define BRUTE_FORCE_MIN_ATTEMPTS 5

/** @brief
 *
 * Stats 常量
 */
#define STATS_EMA_ALPHA_1MIN   0.016f
#define STATS_EMA_ALPHA_5MIN   0.0033f
#define STATS_EMA_ALPHA_15MIN  0.0011f

#endif
