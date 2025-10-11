#include <stdlib.h>
#include <stdio.h>

#include "../../includes/platform.h"
#include "../../includes/http_client.h"
#include "../../includes/platform_webhook.h"

#define PORT 0x01BB
#define USER_AGENT "AnyIntruderWebhook/1.0"
#define CONTENT_TYPE "application/json"
#define CONFIG_PATH "../../config.yaml"

#define TELEGRAM_API_URL "https://api.telegram.org/bot%s/sendMessage"

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

    snprintf(url, sizeof(url), TELEGRAM_API_URL, token);
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