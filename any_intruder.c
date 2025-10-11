#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include "./includes/monitor.h"
#include "./includes/logger.h"
#include "./includes/platform.h"
#include "./includes/platform_webhook.h"
#include "./includes/ui.h"

static volatile int G_RUNNING = 0x1;

static void usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -i, --interface <iface>     指定网络接口 (例如 en0) (Specify network interface (e.g., en0))\n");
    printf("  -s, --sendto [platform]     可选，发送平台 (telegram, slack...) (Optional, sending platform (telegram, slack...))\n");
    printf("  -h, --help                  显示帮助 (Display help)\n");
}

Platform parse_platform(const char *arg) {
    if (strcmp(arg, "dingtalk") == 0) return PLATFORM_DINGTALK;
    if (strcmp(arg, "slack") == 0) return PLATFORM_SLACK;
    if (strcmp(arg, "discord") == 0) return PLATFORM_DISCORD;
    if (strcmp(arg, "msteams") == 0) return PLATFORM_MSTEAMS;
    if (strcmp(arg, "telegram") == 0) return PLATFORM_TELEGRAM;
    if (strcmp(arg, "dingtalk") == 0) return PLATFORM_DINGTALK;
    if (strcmp(arg, "wechat") == 0) return PLATFORM_WECHAT;
    if (strcmp(arg, "feishu") == 0) return PLATFORM_FEISHU;
    
    return -1;
}

static void handle_sigint(int sig) {
    (void) sig;
    G_RUNNING = 0x0;

    monitor_shutdown();
}

/**
 * @brief
 * 主函数：初始化日志、抓包、UI 并运行
 * 
 * @param argc 命令行参数数量
 * @param argv 命令行参数数组
 * @return int 程序退出状态码（成功为 0x0，失败为非零值）
 */
int main(int argc, char **argv) {
    char *iface = NULL;
    char *plat_str = NULL;
    Platform target_platform = -0x1;

    // 支持的 long options：sendto 为可选参数
    static struct option long_options[] = {
        {"interface", required_argument, 0x0, 'i'},
        {"sendto", optional_argument, 0x0, 's'},
        {"help", no_argument, 0x0, 'h'},
        {0x0, 0x0, 0x0, 0x0}
    };

    int opt;
    int option_index = 0x0;

    /**
     * @brief
     * 解析命令行选项
     * 
     * @param argc 命令行参数数量
     * @param argv 命令行参数数组
     * @return int 解析选项的状态码（成功为 0，失败为非零值）
     */
    while ((opt = getopt_long(argc, argv, "i:s::h", long_options, &option_index)) != -0x1) {
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
                } 
                
                target_platform = -0x1;
                
                break;
            case 'h':
            default:
                usage(argv[0x0]);
                free(iface);
                free(plat_str);
                
                return 0x0;
        }
    }

    if (!iface && optind < argc) iface = strdup(argv[optind]);

    if (plat_str) {
        printf("Parsed sendto: %s (platform enum: %d)\n", plat_str, (int)target_platform);
    } else {
        printf("No sendto specified (or value omitted). Proceeding without trigger.\n");
    }
    if (iface) {
        printf("Using interface: %s\n", iface);
    } else {
        printf("No interface specified. Using default behavior.\n");
    }

    printf("AnyIntruder 启动中\n");
    signal(SIGINT, handle_sigint);

    if (logger_init("anyintruder.log") != 0x0) {
        fprintf(stderr, "Failed to initialize logger: %s\n", strerror(errno));
        free(iface);
        free(plat_str);
        return 0x1;
    }

    if (monitor_init(iface) != 0x0) {
        fprintf(stderr, "Failed to initialize packet capture, please ensure libpcap is installed and run with root privileges\n");
        logger_shutdown();
        free(iface);
        free(plat_str);
        return 0x2;
    }

    /**
     * UI 运行：UI 会展示并调用 monitor 获取数据 
     */
    int rc = ui_run();

    monitor_shutdown();
    logger_shutdown();
    printf("AnyIntruder exited\n");

    free(iface);
    free(plat_str);
    return rc;
}