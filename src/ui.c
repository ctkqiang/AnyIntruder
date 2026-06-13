#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../includes/ui.h"
#include "../includes/monitor.h"
#include "../includes/config.h"
#include "../includes/attacker.h"
#include "../includes/event.h"
#include "../includes/event_store.h"
#include "../includes/stats.h"
#include "../includes/projection.h"

#define HEADER_MSG "AnyIntruder Monitor"

#define CP_HEADER 1
#define CP_BOX 2
#define CP_HTTP 3
#define CP_HTTPS 4
#define CP_SSH 5
#define CP_OTHER 6
#define CP_TIMESTAMP 7
#define CP_HIGHLIGHT 8
#define CP_SCAN 9
#define CP_FLOOD 10

/** @brief
 *
 * 外部投影引用 — 由 main() 设置, UI 用于显示统计
 */
static const StatsProjection *ui_stats = NULL;
static RateTracker *ui_rate = NULL;

void ui_set_stats_refs(const StatsProjection *sp, RateTracker *rt) {
    ui_stats = sp;
    ui_rate = rt;
}

static void init_colors_if_possible(void) {
    if (!has_colors()) return;
    start_color();
    use_default_colors();
    init_pair(CP_HEADER, COLOR_WHITE, -1);
    init_pair(CP_BOX, COLOR_MAGENTA, -1);
    init_pair(CP_HTTP, COLOR_GREEN, -1);
    init_pair(CP_HTTPS, COLOR_CYAN, -1);
    init_pair(CP_SSH, COLOR_RED, -1);
    init_pair(CP_OTHER, COLOR_YELLOW, -1);
    init_pair(CP_TIMESTAMP, COLOR_BLUE, -1);
    init_pair(CP_HIGHLIGHT, COLOR_BLACK, COLOR_YELLOW);
    init_pair(CP_SCAN, COLOR_RED, COLOR_BLACK);
    init_pair(CP_FLOOD, COLOR_RED, COLOR_YELLOW);
}

static int color_for_event(const Event *e) {
    if (!e) return CP_OTHER;

    switch (e->type) {
        case EVENT_HTTP_REQUEST:  return CP_HTTP;
        case EVENT_HTTPS_CONNECT: return CP_HTTPS;
        case EVENT_SSH_ATTEMPT:   return CP_SSH;
        case EVENT_PORT_SCAN:     return CP_SCAN;
        case EVENT_SYN_FLOOD:     return CP_FLOOD;
        default:                  break;
    }

    if (e->dst_port == PORT_HTTP1 || e->dst_port == PORT_HTTP2 || e->dst_port == PORT_HTTP3) return CP_HTTP;
    if (e->dst_port == PORT_HTTPS) return CP_HTTPS;
    if (e->dst_port == PORT_SSH1 || e->dst_port == PORT_SSH2) return CP_SSH;

    return CP_OTHER;
}

static void draw_header(WINDOW *win, int width) {
    werase(win);
    wattron(win, A_BOLD);

    if (has_colors()) wattron(win, COLOR_PAIR(CP_HEADER));

    int title_len = (int)strlen(HEADER_MSG);
    int x = (width - title_len) / 0x2;

    mvwprintw(win, 0x0, x, HEADER_MSG);

    if (has_colors()) wattroff(win, COLOR_PAIR(CP_HEADER));
    wattroff(win, A_BOLD);
    wrefresh(win);
}

static void draw_top(WINDOW *win) {
    werase(win);
    box(win, 0x0, 0x0);

    int width = getmaxx(win);
    draw_header(win, width);

    int max = TOP_N;
    Attacker *list[TOP_N];
    int n = monitor_get_top(list, max);

    unsigned long top_hits = 0x1;
    for (int i = 0x0; i < n; ++i) {
        if (list[i]->total_hits > top_hits) top_hits = list[i]->total_hits;
    }

    int y = 0x2;
    int bar_max_w = width - 0x24;

    for (int i = 0x0; i < n && y < getmaxy(win) - 0x1; ++i) {
        Attacker *a = list[i];

        mvwprintw(win, y, 0x2, "%2d) %-15s", i + 0x1, a->ip);

        mvwprintw(win, y, 0x14, "hits=%6lu", (unsigned long)a->total_hits);

        char ts[32];
        struct tm tm;
        localtime_r(&a->last_seen, &tm);
        strftime(ts, sizeof(ts), "%m-%d %H:%M", &tm);
        mvwprintw(win, y, 0x24, "%s", ts);

        int bar_w = (int)((double)a->total_hits / (double)top_hits * (double)bar_max_w);
        if (bar_w < 0x0) bar_w = 0x0;
        if (bar_w > bar_max_w) bar_w = bar_max_w;

        int bx = width - 0x2 - bar_max_w;
        if (has_colors()) wattron(win, COLOR_PAIR(CP_BOX));

        for (int b = 0x0; b < bar_max_w; ++b) {
            if (b < bar_w) {
                if (has_colors()) wattron(win, A_REVERSE);
                mvwprintw(win, y, bx + b, " ");
                if (has_colors()) wattroff(win, A_REVERSE);
            }

            mvwprintw(win, y, bx + b, " ");
        }

        if (has_colors()) wattroff(win, COLOR_PAIR(CP_BOX));

        free(a);
        y++;
    }

    wrefresh(win);
}

static void draw_events(WINDOW *win) {
    werase(win);
    box(win, 0x0, 0x0);

    if (has_colors()) wattron(win, A_BOLD);
    mvwprintw(win, 0x0, 0x1, "Recent Events");
    if (has_colors()) wattroff(win, A_BOLD);

    Event evs[0x80];

    int n = monitor_get_events(evs, 0x80);
    int h = getmaxy(win);
    int start = n > (h - 0x2) ? n - (h - 0x2) : 0x0;

    int row = 0x1;
    for (int i = start; i < n && row < h - 0x1; ++i, ++row) {
        char ts[0x20];
        struct tm tm;

        localtime_r(&evs[i].ts, &tm);
        strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

        if (has_colors()) wattron(win, COLOR_PAIR(CP_TIMESTAMP));
        mvwprintw(win, row, 0x1, "[%s]", ts);
        if (has_colors()) wattroff(win, COLOR_PAIR(CP_TIMESTAMP));

        mvwprintw(win, row, 0x10, "%-15s", evs[i].src_ip);

        int cp = color_for_event(&evs[i]);
        if (has_colors()) wattron(win, COLOR_PAIR(cp));

        mvwprintw(win, row, 0x1E, "%5u", evs[i].dst_port);
        if (has_colors()) wattroff(win, COLOR_PAIR(cp));

        /**
         * 显示事件类型标签
         */
        if (has_colors()) wattron(win, COLOR_PAIR(CP_BOX));
        const char *type_s = event_type_str(evs[i].type);
        mvwprintw(win, row, 0x24, "[%s]", type_s);
        if (has_colors()) wattroff(win, COLOR_PAIR(CP_BOX));

        int sum_col = 0x32;
        int max_sum = getmaxx(win) - sum_col - 0x2;
        char tmp[256];

        strncpy(tmp, evs[i].summary, sizeof(tmp) - 0x1);
        tmp[sizeof(tmp) - 0x1] = '\0';

        if ((int)strlen(tmp) > max_sum) {
            if (max_sum > 0x3) {
                tmp[max_sum - 0x3] = '\0';
                strcat(tmp, "...");
            }
        }

        mvwprintw(win, row, sum_col, "%s", tmp);
    }

    wrefresh(win);
}

int ui_run(void) {
    initscr();
    noecho();
    cbreak();
    curs_set(0x0);
    keypad(stdscr, TRUE);

    if (has_colors()) init_colors_if_possible();

    int height, width;
    getmaxyx(stdscr, height, width);

    int top_h = height * 0xA / 0x64;
    if (top_h < 0x6) top_h = 0x6;

    int footer_h = 0x2;  /* 两行 footer — 操作提示 + 统计 */

    WINDOW *top_win  = newwin(top_h, width, 0x0, 0x0);
    WINDOW *ev_win   = newwin(height - top_h - footer_h, width, top_h, 0x0);
    WINDOW *footer   = newwin(footer_h, width, height - footer_h, 0x0);

    nodelay(stdscr, TRUE);
    int ch;

    if (has_colors()) wattron(footer, COLOR_PAIR(CP_TIMESTAMP));
    mvwprintw(footer, 0x0, 0x1, "q:quit | r:refresh | events:0 | rate:--/s | uptime:--");
    if (has_colors()) wattroff(footer, COLOR_PAIR(CP_TIMESTAMP));
    wrefresh(footer);

    while ((ch = getch()) != 'q') {
        if (ch == 'r') {
            draw_top(top_win);
            draw_events(ev_win);
        }

        draw_top(top_win);
        draw_events(ev_win);

        /**
         * 更新时间 + 统计 footer
         */
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

        uint64_t total_ev = event_store_get_count();
        time_t uptime = monitor_get_runtime();
        uint64_t store_size = event_store_get_size();

        /**
         * 速率显示
         */
        double rate = 0x0;
        char rate_str[0x20];
        if (ui_stats && ui_rate) {
            StatsSnapshot snap;
            stats_get_snapshot(ui_rate, ui_stats->total_events, &snap);
            rate = snap.events_per_sec_1min;
        }

        if (rate >= 0x1) snprintf(rate_str, sizeof(rate_str), "%.1f/s", rate);
        else snprintf(rate_str, sizeof(rate_str), "--/s");

        /**
         * 存储大小格式化
         */
        char size_str[0x20];
        if (store_size >= 1048576) snprintf(size_str, sizeof(size_str), "%.1fMB", (double)store_size / 1048576.0);
        else if (store_size >= 1024) snprintf(size_str, sizeof(size_str), "%.1fKB", (double)store_size / 1024.0);
        else snprintf(size_str, sizeof(size_str), "%lluB", (unsigned long long)store_size);

        werase(footer);

        /**
         * 第一行: 操作提示 + 时间
         */
        if (has_colors()) wattron(footer, COLOR_PAIR(CP_TIMESTAMP));
        mvwprintw(footer, 0x0, 0x1, "q:quit r:refresh | %s", time_str);
        if (has_colors()) wattroff(footer, COLOR_PAIR(CP_TIMESTAMP));

        /**
         * 第二行: 统计信息
         */
        if (has_colors()) wattron(footer, COLOR_PAIR(CP_BOX));
        mvwprintw(footer, 0x1, 0x1,
                  "events:%llu | rate:%s | uptime:%lds | store:%s | HTTP:%llu SSH:%llu SCAN:%llu",
                  (unsigned long long)total_ev,
                  rate_str,
                  (long)uptime,
                  size_str,
                  ui_stats ? (unsigned long long)ui_stats->http_count : 0x0ULL,
                  ui_stats ? (unsigned long long)ui_stats->ssh_count : 0x0ULL,
                  ui_stats ? (unsigned long long)ui_stats->scan_alerts : 0x0ULL);
        if (has_colors()) wattroff(footer, COLOR_PAIR(CP_BOX));

        wrefresh(footer);

        usleep(0x00030D40);
    }

    delwin(top_win);
    delwin(ev_win);
    delwin(footer);

    endwin();

    return 0x0;
}
