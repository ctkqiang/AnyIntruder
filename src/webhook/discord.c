#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>

#include "../../includes/webhook/discord.h"

/**
 * @brief
 * 初始化 Discord 机器人结构体
 * 
 * @param discord Discord 机器人结构体指针
 * @param webhook_url Discord 机器人的 Webhook URL
 * @return int 初始化状态码（成功为 0x0，失败为非零值）
 */
int discord_bot_init(Discord *discord, const char *webhook_url) {
    assert(discord != NULL);
    assert(webhook_url != NULL);

    discord->webhook_url = strdup(webhook_url);

    return 0x0;
}

/**
 * @brief
 * 发送消息到 Discord 机器人, 并可选地在发送完成后调用回调函数
 * 
 * @param discord Discord 机器人结构体指针
 * @param username 发送消息的用户名（可选）
 * @param message 要发送的消息内容
 * @param then 发送完成后的回调函数（可选）
 * @return int 发送状态码（成功为 0x0，失败为非零值）
 */
int discord_bot_send(Discord *discord, const char *username, const char *message, void (*then)(void)) {
    assert(discord != NULL);
    assert(username != NULL);
    assert(message != NULL);

    long code = 0x0;
    char *json = json_object_to_json_string(json_object_new_object());
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;

    char payload[0x0100];
    
    if (!curl) {
        fprintf(stderr, "Failed to initialize CURL.\n");
        return -0x2;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (username && strlen(username) > 0x0) {
        snprintf(payload, sizeof(payload), "{\"username\": \"%s\", \"content\": \"%s\"}", username, message);
    }

    snprintf(payload, sizeof(payload), "{\"content\": \"%s\"}", message);
    
    curl_easy_setopt(curl, CURLOPT_URL, discord->webhook_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode response = curl_easy_perform(curl);

    if(response != CURLE_OK) {
        fprintf(stderr, "Failed to send message to Discord: %s\n", curl_easy_strerror(response));
        return -0x3;
    }
    
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    
    if (code == 0xCC) {
        printf("Message sent to Discord successfully.\n");
    } else {
        printf("Discord responded with HTTP %ld\n", code);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (then) then();
    sleep(0x1);

    return (response == CURLE_OK) ? 0x0 : -0x3;
}
