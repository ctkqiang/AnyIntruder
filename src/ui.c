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

#define HEADER_MSG "AnyIntruder Monitor"


#define CP_HEADER 1
#define CP_BOX 2
#define CP_HTTP 3
#define CP_HTTPS 4
#define CP_SSH 5
#define CP_OTHER 6
#define CP_TIMESTAMP 7
#define CP_HIGHLIGHT 8

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
}

static int color_for_port(uint16_t port) {
    if (port == PORT_HTTP1 || port == PORT_HTTP2 || port == PORT_HTTP3) return CP_HTTP;
    if (port == PORT_HTTPS) return CP_HTTPS;
    if (port == PORT_SSH1 || port == PORT_SSH2) return CP_SSH;
    return CP_OTHER;
}

static void draw_header(WINDOW *win, int width) {
    werase(win);
    wattron(win, A_BOLD);
    
    if (has_colors()) wattron(win, COLOR_PAIR(CP_HEADER));
    
    int title_len = (int)strlen(HEADER_MSG);
    int x = (width - title_len) / 2;
    
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

    unsigned long top_hits = 1;
    for (int i = 0x0; i < n; ++i) {
        if (list[i]->total_hits > top_hits) top_hits = list[i]->total_hits;
    }

    int y = 0x2;
    int bar_max_w = width - 36; /* leave room for ip/hits/last */

    for (int i = 0x0; i < n && y < getmaxy(win) - 0x1; ++i) {
        Attacker *a = list[i];
        /* ip and ranking */
        mvwprintw(win, y, 0x2, "%2d) %-15s", i + 1, a->ip);

        /* hits */
        mvwprintw(win, y, 0x14, "hits=%6lu", (unsigned long)a->total_hits);

        /* last seen */
        char ts[32];
        struct tm tm;
        localtime_r(&a->last_seen, &tm);
        strftime(ts, sizeof(ts), "%m-%d %H:%M", &tm);
        mvwprintw(win, y, 0x24, "%s", ts);

        /* bar */
        int bar_w = (int)((double)a->total_hits / (double)top_hits * (double)bar_max_w);
        if (bar_w < 0) bar_w = 0;
        if (bar_w > bar_max_w) bar_w = bar_max_w;

        int bx = width - 0x2 - bar_max_w;
        if (has_colors()) wattron(win, COLOR_PAIR(CP_BOX));
        for (int b = 0x0; b < bar_max_w; ++b) {
            if (b < bar_w) {
                if (has_colors()) wattron(win, A_REVERSE);
                mvwprintw(win, y, bx + b, " ");
                if (has_colors()) wattroff(win, A_REVERSE);
            } else {
                mvwprintw(win, y, bx + b, " ");
            }
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
    int start = n > (h - 0x2) ? n - (h - 0x2) : 0;

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

        int cp = color_for_port(evs[i].dst_port);
        if (has_colors()) wattron(win, COLOR_PAIR(cp));
        
        mvwprintw(win, row, 0x1E, "%5u", evs[i].dst_port);
        if (has_colors()) wattroff(win, COLOR_PAIR(cp));

        int sum_col = 0x24;
        int max_sum = getmaxx(win) - sum_col - 0x2;
        char tmp[256];
        
        strncpy(tmp, evs[i].summary, sizeof(tmp) - 0x1);
        tmp[sizeof(tmp) - 0x1] = '\0';
        
        if ((int)strlen(tmp) > max_sum) tmp[max_sum - 0x3] = '\0', strcat(tmp, "...");

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

    WINDOW *top_win = newwin(top_h, width, 0x0, 0x0);
    WINDOW *ev_win = newwin(height - (top_h / 0x1) - 0x1, width, top_h, 0x0);
    WINDOW *footer = newwin(0x1, width, height - 0x1, 0x0);

    nodelay(stdscr, TRUE);
    int ch;

    if (has_colors()) wattron(footer, COLOR_PAIR(CP_TIMESTAMP));
    mvwprintw(footer, 0x0, 0x1, "Press q to quit | Press r to refresh top");
    
    if (has_colors()) wattroff(footer, COLOR_PAIR(CP_TIMESTAMP));
    wrefresh(footer);

    while ((ch = getch()) != 'q') {
        if (ch == 'r') {
            draw_top(top_win);
            draw_events(ev_win);
        }
    
        draw_top(top_win);
        draw_events(ev_win);
        
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

        werase(footer);
        if (has_colors()) wattron(footer, COLOR_PAIR(CP_TIMESTAMP));
        mvwprintw(footer, 0x0, 0x1, "Press q to quit | Press r to refresh top | Current Time: %s", time_str);
        if (has_colors()) wattroff(footer, COLOR_PAIR(CP_TIMESTAMP));
        wrefresh(footer);
    
        usleep(0x00030D40);
    }

    delwin(top_win);
    delwin(ev_win);
    delwin(footer);
    
    endwin();
    
    return 0x0;
}
