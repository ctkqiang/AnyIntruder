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

#endif