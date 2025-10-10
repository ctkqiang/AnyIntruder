#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "./includes/monitor.h"
#include "./includes/logger.h"
#include "./includes/ui.h"
#include <errno.h> // Include errno.h for errno and strerror
#include <string.h> // Include string.h for strerror

static volatile int G_RUNNING = 0x1;
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
 * @return int 程序退出状态码（成功为 0，失败为非零值）
 */
int main(int argc, char **argv) {
    const char *iface = NULL;
    if (argc > 0x1) iface = argv[0x1];

    printf("AnyIntruder 启动中\n");
    signal(SIGINT, handle_sigint);
    
    if (logger_init("anyintruder.log") != 0x0) {
        fprintf(stderr, "日志初始化失败: %s\n", strerror(errno));
        
        return 0x1;
    }

    if (monitor_init(iface) != 0x0) {
        fprintf(stderr, "抓包初始化失败，请确保已安装 libpcap 并使用 root 权限\n");

        return 0x2;
    }

    /**
     * UI 运行：UI 会展示并调用 monitor 获取数据 
     */
    int rc = ui_run();

    monitor_shutdown();
    logger_shutdown();
    printf("AnyIntruder 退出\n");
 
    return rc;
}