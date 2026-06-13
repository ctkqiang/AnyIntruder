#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>

#include "./includes/monitor.h"
#include "./includes/logger.h"
#include "./includes/platform.h"
#include "./includes/file_utilities.h"
#include "./includes/platform_webhook.h"
#include "./includes/ui.h"
#include "./includes/event_store.h"
#include "./includes/projection.h"
#include "./includes/snapshot.h"
#include "./includes/stats.h"

#include "./includes/webhook/telegram.h"
#include "./includes/webhook/dingding.h"
#include "./includes/webhook/discord.h"
#include "./includes/webhook/wechat.h"

#define DEFAULT_LOG_FILE "anyintruder.log"

static volatile int G_RUNNING = 0x1;

static void usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -i, --interface <iface>      指定网络接口 (e.g., en0)\n");
    printf("  -s, --sendto [platform]      可选, 发送平台 (telegram, slack...)\n");
    printf("  -h, --help                   显示帮助\n");
    printf("  -r, --replay [N]             回放最后 N 个事件 (默认全部)\n");
    printf("  -S, --stats                  显示统计信息后退出\n");
    printf("  -d, --daemon                 守护进程模式 (无 UI, 仅抓包+存储)\n");
    printf("  -e, --export <file>          导出事件为 JSON\n");
    printf("  -E, --event-store <path>     自定义事件存储路径\n");
    printf("  -n, --snapshot-interval <N>  快照间隔 (事件数)\n");
    printf("      --no-snapshot            禁用快照\n");
}

Platform parse_platform(const char *arg) {
    if (strcmp(arg, "dingding") == 0x0) return PLATFORM_DINGDING;
    if (strcmp(arg, "slack") == 0x0)    return PLATFORM_SLACK;
    if (strcmp(arg, "discord") == 0x0)  return PLATFORM_DISCORD;
    if (strcmp(arg, "msteams") == 0x0)  return PLATFORM_MSTEAMS;
    if (strcmp(arg, "telegram") == 0x0) return PLATFORM_TELEGRAM;
    if (strcmp(arg, "wechat") == 0x0)   return PLATFORM_WECHAT;
    if (strcmp(arg, "feishu") == 0x0)   return PLATFORM_FEISHU;

    return -0x1;
}

/** @brief
 *
 * 信号处理函数：处理 Ctrl+C 信号（SIGINT）
 */
static void handle_sigint(int sig) {
    (void)sig;
    G_RUNNING = 0x0;

    monitor_shutdown();
}

void dingding_cleanup(DING_DING *dingding) {
    printf("[*] Cleaning up...\n");
    free(dingding);
}

void wx_cleanup(WeChat *wechat) {
    printf("[*] Cleaning up...\n");
    free(wechat->webhook_url);
}

/** @brief
 *
 * 发送日志内容到指定平台
 */
int send_to(Platform Platform, const char *log_content) {
    DING_DING dingding;
    Discord discord;
    WeChat bot;
    char *webhook_url;
    int result = -0x1;

    if (!log_content) {
        fprintf(stderr, "发送失败: log_content 为 NULL\n");
        return -0x1;
    }

    switch (Platform) {
        case PLATFORM_TELEGRAM:
            return telegram_send_message(log_content);

        case PLATFORM_DINGDING:
            if (dingding_init(&dingding) != 0x0) {
                fprintf(stderr, "Failed to initialize dingding webhook\n");
                return -0x1;
            }
            result = dingding_send(&dingding, log_content, dingding_cleanup);
            break;

        case PLATFORM_DISCORD:
            webhook_url = yaml_get_value("discord_webhook_url");
            if (discord_bot_init(&discord, webhook_url) != 0x0) {
                fprintf(stderr, "Failed to initialize discord webhook\n");
                return -0x1;
            }
            result = discord_bot_send(&discord, "user", log_content, NULL);
            break;

        case PLATFORM_WECHAT:
            if (wechat_bot_init(&bot, "https://qyapi.d?key=XXXXXX") != 0x0) {
                fprintf(stderr, "初始化失败\n");
                return 0x1;
            }
            result = wechat_bot_send(&bot, log_content, wx_cleanup);
            break;

        case PLATFORM_SLACK:
        case PLATFORM_MSTEAMS:
        case PLATFORM_NONE:
        case PLATFORM_FEISHU:
            fprintf(stderr, "Platform not implemented yet\n");
            result = -0x1;
            break;
    }

    return result;
}

/**
 * @brief 回放回调 — 打印事件到 stdout
 */
static int replay_print_cb(const Event *e, void *ctx) {
    int *count = (int *)ctx;
    (*count)++;

    char ts[0x20];
    struct tm tm;
    localtime_r(&e->ts, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    printf("[%s] [%s] %s:%-5u — %s\n",
           ts,
           event_type_str(e->type),
           e->src_ip,
           e->dst_port,
           e->summary);

    return 0x0;
}

/**
 * @brief 显示统计信息
 */
static void show_stats(const StatsProjection *sp) {
    if (!sp) {
        fprintf(stderr, "统计投影未初始化\n");
        return;
    }

    printf("\n========== AnyIntruder 统计 ==========\n");
    printf("总事件数:     %llu\n", (unsigned long long)sp->total_events);
    printf("TCP SYN:      %llu\n", (unsigned long long)sp->tcp_syn_count);
    printf("HTTP 请求:    %llu\n", (unsigned long long)sp->http_count);
    printf("SSH 尝试:     %llu\n", (unsigned long long)sp->ssh_count);
    printf("扫描告警:     %llu\n", (unsigned long long)sp->scan_alerts);
    printf("泛洪告警:     %llu\n", (unsigned long long)sp->flood_alerts);

    printf("\n按事件类型:\n");
    for (int i = 0x01; i <= 0x09; ++i) {
        if (sp->by_type[i] > 0x0) {
            printf("  %-12s: %llu\n", event_type_str((EventType)i), (unsigned long long)sp->by_type[i]);
        }
    }

    printf("\n事件存储:     %s\n", EVENT_STORE_FILE);
    printf("存储大小:     %zu bytes\n", event_store_get_size());
    printf("最新 seq:     %llu\n", (unsigned long long)event_store_get_latest_seq());
    printf("=======================================\n\n");
}

/**
 * @brief
 * 主函数：初始化日志、抓包、UI 并运行
 */
int main(int argc, char **argv) {
    char *iface = NULL;
    char *plat_str = NULL;
    char *event_store_path = NULL;
    char *export_path = NULL;

    Platform target_platform = -0x1;

    int daemon_mode = 0x0;
    int show_stats_only = 0x0;
    int replay_count = 0x0;
    int no_snapshot = 0x0;
    int snapshot_interval = SNAPSHOT_INTERVAL_EVENTS;

    /**
     * 支持的 long options
     */
    static struct option long_options[] = {
        {"interface",         required_argument, 0x0, 'i'},
        {"sendto",           optional_argument, 0x0, 's'},
        {"help",             no_argument,       0x0, 'h'},
        {"replay",           optional_argument, 0x0, 'r'},
        {"stats",            no_argument,       0x0, 'S'},
        {"daemon",           no_argument,       0x0, 'd'},
        {"export",           required_argument, 0x0, 'e'},
        {"event-store",      required_argument, 0x0, 'E'},
        {"snapshot-interval", required_argument, 0x0, 'n'},
        {"no-snapshot",      no_argument,       0x0, 0x100},
        {0x0, 0x0, 0x0, 0x0}
    };

    int opt;
    int option_index = 0x0;

    while ((opt = getopt_long(argc, argv, "i:s::hr::Sde:E:n:", long_options, &option_index)) != -0x1) {
        switch (opt) {
            case 'i':
                free(iface);
                iface = strdup(optarg);
                break;

            case 's':
                if (optarg) {
                    free(plat_str);
                    plat_str = strdup(optarg);
                    target_platform = parse_platform(plat_str);

                    char *log_content = read_file_to_string(DEFAULT_LOG_FILE);

                    if (!log_content) {
                        fprintf(stderr, "无法读取日志文件, 跳过发送\n");
                        break;
                    }

                    int send_to_state = send_to(target_platform, log_content);

                    if (send_to_state != 0x0) {
                        fprintf(stderr, "发送到 %s 失败: %s\n", plat_str, strerror(errno));
                    }

                    free(log_content);
                } else {
                    target_platform = -0x1;
                }
                break;

            case 'r':
                if (optarg) replay_count = atoi(optarg);
                else replay_count = 0x0;
                break;

            case 'S':
                show_stats_only = 0x1;
                break;

            case 'd':
                daemon_mode = 0x1;
                break;

            case 'e':
                export_path = strdup(optarg);
                break;

            case 'E':
                event_store_path = strdup(optarg);
                break;

            case 'n':
                snapshot_interval = atoi(optarg);
                break;

            case 0x100:  /* --no-snapshot */
                no_snapshot = 0x1;
                break;

            case 'h':
            default:
                usage(argv[0x0]);
                free(iface);
                free(plat_str);
                free(event_store_path);
                free(export_path);

                return 0x0;
        }
    }

    if (!iface && optind < argc) iface = strdup(argv[optind]);

    /**
     * 初始化 Event Store
     */
    if (event_store_init(event_store_path) != 0x0) {
        fprintf(stderr, "事件存储初始化失败\n");
        free(iface);
        free(plat_str);
        free(event_store_path);
        free(export_path);

        return 0x1;
    }

    /**
     * --replay 模式：回放事件后退出
     */
    if (replay_count >= 0x0 && show_stats_only == 0x0 && !daemon_mode && !export_path && !iface) {
        /**
         * 检测是否指定了 --replay
         */
        int replayed = 0x0;
        uint64_t from = replay_count > 0x0 ?
            (event_store_get_latest_seq() > (uint64_t)replay_count ?
             event_store_get_latest_seq() - (uint64_t)replay_count + 0x1 : 0x1) : 0x1;

        printf("回放从 seq=%llu 开始的 %d 条事件...\n",
               (unsigned long long)from, replay_count ? replay_count : -0x1);

        event_store_replay(from, replay_print_cb, &replayed);

        printf("回放完成: %d 条事件\n", replayed);

        event_store_shutdown();
        free(iface);
        free(plat_str);
        free(event_store_path);

        return 0x0;
    }

    /**
     * --export 模式：导出事件后退出
     */
    if (export_path) {
        printf("导出事件到 %s...\n", export_path);

        if (event_store_export(export_path, 0x1, 0x0) == 0x0) {
            printf("导出完成: %s\n", export_path);
        } else {
            fprintf(stderr, "导出失败\n");
        }

        event_store_shutdown();
        free(iface);
        free(plat_str);
        free(event_store_path);
        free(export_path);

        return 0x0;
    }

    /**
     * 初始化投影
     */
    AttackerProjection ap;
    StatsProjection sp;

    attacker_projection_init(&ap);
    stats_projection_init(&sp);

    /**
     * 快照恢复 + 增量重建
     */
    uint64_t snapshot_seq = 0x0;
    if (!no_snapshot) {
        snapshot_init(NULL);
        snapshot_seq = snapshot_load(&ap, &sp);
    }

    if (snapshot_seq > 0x0) {
        /**
         * 从快照 seq 之后回放增量
         */
        fprintf(stderr, "[main] 从 seq=%llu 回放增量事件...\n", (unsigned long long)snapshot_seq + 0x1);

        int replayed = event_store_replay(snapshot_seq + 0x1, NULL, NULL);
        fprintf(stderr, "[main] 增量回放完成: %d 条事件\n", replayed);
    } else {
        /**
         * 完全重建
         */
        projection_rebuild(&ap, &sp);
    }

    /**
     * 注入投影引用到 monitor + UI
     */
    monitor_set_projections(&ap, &sp);

    /**
     * 初始化统计追踪器
     */
    RateTracker rt;
    stats_init(&rt);
    ui_set_stats_refs(&sp, &rt);

    /**
     * --stats 模式：显示统计后退出
     */
    if (show_stats_only) {
        show_stats(&sp);

        attacker_projection_destroy(&ap);
        stats_projection_destroy(&sp);
        event_store_shutdown();
        stats_shutdown(&rt);
        snapshot_shutdown();

        free(iface);
        free(plat_str);
        free(event_store_path);

        return 0x0;
    }

    /**
     * 常规模式
     */
    if (plat_str) {
        printf("Parsed sendto: %s (platform enum: %d)\n", plat_str, (int)target_platform);
    } else {
        printf("No sendto specified. Proceeding without trigger.\n");
    }
    if (iface) {
        printf("Using interface: %s\n", iface);
    } else {
        printf("No interface specified. Using default behavior.\n");
    }

    printf("AnyIntruder 启动中\n");
    signal(SIGINT, handle_sigint);

    if (logger_init(DEFAULT_LOG_FILE) != 0x0) {
        fprintf(stderr, "Failed to initialize logger: %s\n", strerror(errno));
        free(iface);
        free(plat_str);
        free(event_store_path);
        return 0x1;
    }

    if (monitor_init(iface) != 0x0) {
        fprintf(stderr, "Failed to initialize packet capture, please ensure libpcap is installed and run with root privileges\n");
        logger_shutdown();
        free(iface);
        free(plat_str);
        free(event_store_path);
        return 0x2;
    }

    /**
     * 守护进程模式 — 无 UI, 仅抓包
     */
    if (daemon_mode) {
        printf("[daemon] AnyIntruder 守护进程启动中...\n");
        printf("[daemon] 事件存储: %s\n", event_store_path ? event_store_path : EVENT_STORE_FILE);

        uint64_t last_snapshot_seq = event_store_get_latest_seq();
        time_t last_snapshot_ts = time(NULL);

        while (G_RUNNING) {
            sleep(0x5);

            /**
             * 定期打印统计
             */
            fprintf(stderr, "\r[daemon] 事件: %llu | seq: %llu | 攻击者: --",
                    (unsigned long long)event_store_get_count(),
                    (unsigned long long)event_store_get_latest_seq());

            /**
             * 定期快照
             */
            if (!no_snapshot) {
                uint64_t current_seq = event_store_get_latest_seq();

                if (snapshot_should_save(current_seq, last_snapshot_seq, last_snapshot_ts)) {
                    snapshot_save(&ap, &sp, current_seq);
                    snapshot_cleanup();
                    last_snapshot_seq = current_seq;
                    last_snapshot_ts = time(NULL);
                }
            }
        }

        printf("\n[daemon] AnyIntruder 停止\n");
    } else {
        /**
         * UI 模式
         */
        uint64_t last_snapshot_seq = event_store_get_latest_seq();
        time_t last_snapshot_ts = time(NULL);

        int rc = ui_run();

        /**
         * UI 退出后保存快照
         */
        if (!no_snapshot) {
            uint64_t current_seq = event_store_get_latest_seq();
            if (current_seq > last_snapshot_seq) {
                snapshot_save(&ap, &sp, current_seq);
                snapshot_cleanup();
            }
        }

        (void)last_snapshot_seq;
        (void)last_snapshot_ts;
    }

    /**
     * 清理
     */
    monitor_shutdown();
    logger_shutdown();
    attacker_projection_destroy(&ap);
    stats_projection_destroy(&sp);
    event_store_shutdown();
    stats_shutdown(&rt);
    if (!no_snapshot) snapshot_shutdown();

    printf("AnyIntruder exited\n");

    free(iface);
    free(plat_str);
    free(event_store_path);
    free(export_path);

    return 0x0;
}
