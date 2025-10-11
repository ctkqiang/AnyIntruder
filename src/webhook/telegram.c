#include <stdlib.h>
#include <stdio.h>

#include "../../includes/platform.h"
#include "../../includes/http_client.h"
#include "../../includes/platform_webhook.h"

#define PORT 0x01BB
#define USER_AGENT "AnyIntruderWebhook/1.0"
#define CONTENT_TYPE "application/json"
#define CONFIG_PATH "../../config.yaml"

/**
 * @brief 从配置文件中获取指定键的值
 * 
 * @param key 配置项的键名
 * @return char* 键对应的值，若未找到或发生错误则返回 NULL
 */
static char *yaml_get_value(const char *key) {
    FILE *fp = fopen(CONFIG_PATH, "r");

    if (!fp) {
        fprintf(stderr, "无法打开配置文件 %s\n", CONFIG_PATH);
        return NULL;
    }

    char line[0x0200];
    char *result = NULL;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0x0] == '#' || strlen(line) < 0x3) continue;

        char *pos = strstr(line, key);
        if (pos) {
            char *colon = strchr(pos, ':');

            if (colon) {
                colon++;

                while (*colon == ' ' || *colon == '\t') colon++;
                char *end = strchr(colon, '\n');

                if (end) *end = '\0';

                result = strdup(colon);

                break;
            }
        }
    }

    fclose(fp);

    return result;
}


/**
 * @brief 发送 Telegram 消息
 * 
 * @param text 要发送的消息文本
 * @return int 发送状态码，0x0 表示成功，-0x1 表示失败
 */
int telegram_send_message(const char *text) {
    char *token = yaml_get_value("bot_token");
    char *chat_id = yaml_get_value("chat_id");

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