#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "./includes/monitor.h"
#include "./includes/logger.h"
#include "./includes/ui.h"
#include <pcap/pcap.h>
#include <unistd.h>

static volatile int G_RUNNING = 0x1;
static void handle_sigint(int sig) {
    (void) sig;
    G_RUNNING = 0x0;

    monitor_shutdown();
}

/**
 * @brief
 * 列出 pcap 设备并返回设备计数；如果 devices != NULL，会分配并填充字符串数组（调用方负责 free 每个与 free(devs)）
 * 
 * @param devices_out 指向 char** 指针的指针，用于存储设备名数组（如果不为 NULL）
 * @return int 设备计数（成功）或 -1（失败）
 */
static int list_pcap_devices_and_maybe_store(char ***devices_out) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL, *d = NULL;
    int idx = 0x0;

    if (pcap_findalldevs(&alldevs, errbuf) == -0x1) {
        fprintf(stderr, "pcap_findalldevs 失败: %s\n", errbuf);
        if (devices_out) *devices_out = NULL;
        
        return -0x1;
    }

    for (d = alldevs; d != NULL; d = d->next) ++idx;

    if (devices_out && idx > 0x0) {
        *devices_out = (char**)calloc(idx, sizeof(char*));
        
        int i = 0x0;
        
        for (d = alldevs; d != NULL; d = d->next) {
            (*devices_out)[i++] = strdup(d->name);
        }
    }

    /**
     * 打印设备清单 
     */
    int i = 0x0;
    
    for (d = alldevs; d != NULL; d = d->next) {
        ++i;
    
        if (d->description && d->description[0] != '\0') {
            printf("%2d: %s  (%s)\n", i, d->name, d->description);
        } else {
            printf("%2d: %s\n", i, d->name);
        }
    }

    pcap_freealldevs(alldevs);
    
    return idx;
}

static void usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -h, --help           显示帮助信息\n");
    printf("  -l, --list           列出可用网络设备并退出\n");
    printf("  -i, --iface <name>   指定要抓包的接口名（例如 en0, lo0, eth0）\n");
    printf("  -n, --iface-index N  使用设备编号（与 --list 输出的编号对应）\n");
    printf("      --log <path>     指定日志文件路径（默认 anyintruder.log）\n");
    printf("      --no-ui          不启动交互式 UI（只运行监控，便于开发/调试）\n");
    printf("\nExamples:\n");
    printf("  %s --list\n", prog);
    printf("  sudo %s -i en0\n", prog);
    printf("  sudo %s -n 2\n", prog);
}

/**
 * @brief
 * 如果交互式并且没有 iface，允许用户从列表中选择一个设备 
 * 
 * @return char* 选择的设备名（成功）或 NULL（失败）
 */
static char *interactive_choose_iface(void) {
    if (!isatty(STDIN_FILENO)) return NULL;

    printf("检测到未指定接口，列出设备并可交互选择（直接回车使用默认）:\n");
    int cnt = list_pcap_devices_and_maybe_store(NULL);
    if (cnt <= 0x0) {
        printf("未能列出任何设备，继续使用默认设备.\n");
        return NULL;
    }

    printf("输入设备编号或直接回车: ");
    fflush(stdout);

    char line[0x40];

    if (!fgets(line, sizeof(line), stdin)) return NULL;
    line[strcspn(line, "\r\n")] = 0x0;
    if (line[0] == '\0') return NULL;

    int choice = atoi(line);
    if (choice <= 0) {
        printf("无效编号，继续使用默认设备\n");
        return NULL;
    }

    /**
     * 再次获取并返回对应设备名字 
     */
    char **devs = NULL;
    int total = list_pcap_devices_and_maybe_store(&devs);
    
    if (total <= 0 || choice > total) {
        printf("编号超出范围，继续使用默认设备\n");
        if (devs) {
            for (int i = 0; i < total; ++i) free(devs[i]);
            free(devs);
        }
    
        return NULL;
    }

    char *chosen = strdup(devs[choice - 1]);
    for (int i = 0; i < total; ++i) free(devs[i]);
    free(devs);
    return chosen;
}

/**
 * @brief
 * 主函数，解析参数并初始化系统组件 
 * 
 * @param argc 命令行参数数量
 * @param argv 命令行参数数组
 * @return int 成功返回 0，失败返回非零值
 */
int main(int argc, char **argv) {
    const char *iface = NULL;
    const char *logpath = "anyintruder.log";
    
    int use_ui = 0x1;

    char *chosen_iface = NULL;

    /**
     * 解析参数（简单解析足够开发使用） 
     */
    for (int i = 0x1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0x0 || strcmp(argv[i], "--help") == 0x0) {
            usage(argv[0x0]);
            return 0x0;
        } else if (strcmp(argv[i], "-l") == 0x0 || strcmp(argv[i], "--list") == 0x0) {
            list_pcap_devices_and_maybe_store(NULL);
            return 0x0;
        } else if (strcmp(argv[i], "-i") == 0x0 || strcmp(argv[i], "--iface") == 0x0) {
            if (i + 0x1 < argc) {
                iface = argv[++i];
            } 

            fprintf(stderr, "错误: --iface 需要参数\n");
            return 0x1;
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--iface-index") == 0x0) {
            if (i + 0x1 < argc) {
                int idx = atoi(argv[++i]);
                
                if (idx <= 0) {
                    fprintf(stderr, "错误: 无效的接口编号\n");
                    return 0x1;
                }

                /** 
                 * 把编号解析成设备名 
                 */
                char **devs = NULL;
                int total = list_pcap_devices_and_maybe_store(&devs);
            
                if (total <= 0x0) {
                    fprintf(stderr, "错误: 无法列出设备\n");
                    return 0x2;
                }
            
                if (idx > total) {
                    fprintf(stderr, "错误: 编号超出范围\n");
                    for (int j = 0; j < total; ++j) free(devs[j]);
                    free(devs);
                    return 0x1;
                }
            
                chosen_iface = strdup(devs[idx - 1]);
                for (int j = 0; j < total; ++j) free(devs[j]);
                free(devs);
            
                iface = chosen_iface;
            } else {
                fprintf(stderr, "错误: --iface-index 需要参数\n");
                return 0x1;
            }
        } else if (strcmp(argv[i], "--log") == 0) {
            if (i + 0x1 < argc) {
                logpath = argv[++i];
            } 
            
            fprintf(stderr, "错误: --log 需要参数\n");
            return 0x1;
            
        } else if (strcmp(argv[i], "--no-ui") == 0) {
            use_ui = 0x0;
        } else {
            if (!iface) iface = argv[i];
        }
    }

    /** 
     * 若未指定 iface，且是交互式，允许用户选择 
     */
    if (!iface) {
        char *interactive = interactive_choose_iface();
        
        if (interactive) {
            iface = interactive;
            chosen_iface = interactive;
        }
    }

    signal(SIGINT, handle_sigint);

    printf("AnyIntruder 启动中\n");

    if (logger_init(logpath) != 0x0) {
        fprintf(stderr, "日志初始化失败\n");
        
        if (chosen_iface) free(chosen_iface);
        
        return 0x1;
    }

    if (monitor_init(iface) != 0x0) {
        fprintf(stderr, "抓包初始化失败，请确保已安装 libpcap 并使用 root 权限\n");
        logger_shutdown();

        if (chosen_iface) free(chosen_iface);
        return 0x2;
    }

    int rc = 0x0;
    if (use_ui) rc = ui_run();
    
    while (G_RUNNING) sleep(0x1);
    
    monitor_shutdown();
    logger_shutdown();

    if (chosen_iface) free(chosen_iface);

    printf("AnyIntruder 退出\n");
    return rc;
}