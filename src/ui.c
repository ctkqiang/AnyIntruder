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

/**
 * 绘制窗口头部信息
 * 
 * 该函数在指定窗口的顶部位置显示预定义的头部消息，并刷新窗口显示。
 * 
 * @param win 指向目标窗口的指针，用于显示头部信息
 */
static void draw_header(WINDOW *win) {
    mvwprintw(win, 0x0, 0x1, HEADER_MSG);
    wrefresh(win);
}

/**
 * 绘制顶部攻击者统计窗口
 * 
 * 该函数负责在指定窗口中绘制攻击者排行榜，显示访问量最高的攻击者IP地址
 * 及其访问统计信息
 * 
 * @param win 要绘制的窗口指针
 */
static void draw_top(WINDOW *win) {
    werase(win);
    box(win, 0x0, 0x0);
    draw_header(win);

    int max = TOP_N;
    Attacker *list[TOP_N];
    
    int n = monitor_get_top(list, max);
    int y = 0x2;

    for (int i = 0; i < n && y < getmaxy(win) - 0x1; ++i) {
        mvwprintw(win, y, 0x2, "%2d) %s  hits=%lu last=%ld", i+1, list[i]->ip, (unsigned long)list[i]->total_hits, (long)list[i]->last_seen);
        free(list[i]);
        
        y++;
    }

    wrefresh(win);
}

/**
 * @brief 绘制事件日志窗口
 * 
 * 该函数负责在指定窗口中绘制最近的事件日志，显示攻击尝试记录
 * 
 * @param win 要绘制的窗口指针
 */
static void draw_events(WINDOW *win) {
    werase(win);
    box(win, 0x0, 0x0);
    mvwprintw(win, 0x0, 0x1, "Recent Events");
 
    Event evs[0x80];
 
    int n = monitor_get_events(evs, 0x80);
    int h = getmaxy(win);
    int start = n > (h - 2) ? n - (h - 2) : 0;
 
    for (int i = start, row = 0x1; i < n && row < h - 0x1; ++i, ++row) {
        char ts[0x20];
        struct tm tm;

        localtime_r(&evs[i].ts, &tm);
        strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
        mvwprintw(win, row, 0x1, "[%s] %s:%u %s", ts, evs[i].src_ip, evs[i].dst_port, evs[i].summary);
    }
 
    wrefresh(win);
}

/**
 * @brief 运行用户界面主循环
 * 
 * 该函数初始化NCurses库，创建顶部攻击者统计窗口和事件日志窗口，
 * 并进入主循环以持续更新和显示统计信息和事件日志。
 * 
 * @return int 程序退出状态码，0表示成功
 */
int ui_run(void) {
    initscr();
    noecho();
    cbreak();
    curs_set(0x0);

    int height, width;
    
    getmaxyx(stdscr, height, width);

    int top_h = height * 0x40 / 0x64;
    
    if (top_h < 0x6) top_h = 0x6;
    
    WINDOW *top_win = newwin(top_h, width, 0x0, 0x0);
    WINDOW *ev_win = newwin(height - top_h, width, top_h, 0x0);

    nodelay(stdscr, TRUE);
    int ch;

    while ((ch = getch()) != 'q') {
        draw_top(top_win);
        draw_events(ev_win);
        
        usleep(0x00030D40); 
    }

    delwin(top_win);
    delwin(ev_win);
    endwin();

    return 0x0;
}