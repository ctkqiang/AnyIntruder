#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../../includes/platform.h"
#include "../../includes/http_client.h"
#include "../../includes/platform_webhook.h"
#include "../../includes/file_utilities.h"

#define PORT 0x01BB
#define USER_AGENT "AnyIntruderWebhook/1.0"
#define CONTENT_TYPE "application/json"

/**
 * @brief 发送 Telegram 消息
 * 
 * @param text 要发送的消息文本
 * @return int 发送状态码，0x0 表示成功，-0x1 表示失败
 */
int telegram_send_message(const char *text) {
    char *token = yaml_get_value("telegram.bot_token");
    char *chat_id = yaml_get_value("telegram.chat_id");

    char url[0x200];
    char json[0x400];

    if (!token || !chat_id) {
        fprintf(stderr, "Failed to read Telegram token or chat_id from config.yaml\n");
        
        free(token);
        free(chat_id);
        
        return -0x1;
    }

    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", token);
    snprintf(
        json, 
        sizeof(json), 
        "{\"chat_id\":\"%s\",\"text\":\"%s\",\"parse_mode\":\"HTML\"}", 
        chat_id, 
        text
    );

    int rc = webhook_send(PLATFORM_TELEGRAM, url, json);

    free(token);
    free(chat_id);

    return rc;
}