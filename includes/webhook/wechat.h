#pragma once

#ifndef WECHAT_H
#define WECHAT_H

#include <stddef.h>

typedef struct {
    char *webhook_url;
} WeChat;

/**
 * 初始化 WeChat Bot 客户端
 * @param wechat - WeChatBot 实例
 * @param webhook_url - 企业微信机器人 Webhook 完整 URL
 */
int wechat_bot_init(WeChat *wechat, const char *webhook_url);

/**
 * 发送文本消息到企业微信群机器人
 * @param wechat - WeChatBot 实例
 * @param message - 文本内容
 * @param then - 发送完成回调函数（可为空）
 */
int wechat_bot_send(WeChat *wechat, const char *message, void (*then)(WeChat *));

#endif