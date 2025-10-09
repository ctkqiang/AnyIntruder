#pragma once

#ifndef LOGGER_H
#define LOGGER_H

#include "monitor.h"

/** @brief
 * 
 * 初始化日志
 */
int logger_init(const char *path);

/** @brief
 * 
 * 写事件日志
 */
void logger_log_event(const Event *e);

/** @brief
 * 
 * 写攻击者快照（可选）
 */
void logger_log_attacker(const Attacker *a);

/** @brief
 * 
 * 关闭日志
 */
void logger_shutdown(void);

#endif