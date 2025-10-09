#pragma once

#include "event.h"
#include "attacker.h"

#ifndef MONITOR_H
#define MONITOR_H

/** @brief
 * 
 * 初始化抓包器，iface 为空时自动选第一个设备
 */
int monitor_init(const char *iface);

/** @brief
 * 
 * 启动主循环（阻塞）
 */
void monitor_loop(void);

/** @brief
 * 
 * 获取最近事件（非线程安全，仅供 UI 读取）
 */
int monitor_get_events(Event *out, int max);

/** @brief
 * 
 * 获取 top 攻击者快照（非线程安全，仅供 UI 读取）
 */
int monitor_get_top(Attacker **out, int max);

/** @brief
 * 
 * 获取当前运行时间（秒）
 */
void monitor_shutdown(void);

#endif