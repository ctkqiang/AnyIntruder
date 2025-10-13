#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>

#include "../../includes/webhook/wechat.h"

int wechat_bot_init(WeChat *wechat, const char *webhook_url) {
    if (!wechat || !webhook_url) {
        fprintf(stderr, "[WeChat] 初始化失败：参数为空。\n");
        return -0x1;
    }

    size_t len = strlen(webhook_url);
    wechat->webhook_url = (char *)malloc(len + 0x1);

    if (!wechat->webhook_url) {
        fprintf(stderr, "[WeChat] 内存分配失败。\n");
        return -0x2;
    }

    strcpy(wechat->webhook_url, webhook_url);
    return 0x0;
}

/**
 * @brief
 * 企业微信发送文本消息（使用官方 webhook REST 接口）
 * 文档参考：https://developer.work.weixin.qq.com/document/path/91770
 */
int wechat_bot_send(WeChat *wechat, const char *message, void (*then)(void)) {
    char payload[0x1000];
 
    if (!wechat || !wechat->webhook_url || !message) {
        fprintf(stderr, "[WeChat] 参数错误。\n");
        return -0x1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "[WeChat] 初始化 libcurl 失败。\n");
        return -0x2;
    }

    snprintf(payload, sizeof(payload), "{\"msgtype\":\"text\",\"text\":{\"content\":\"%s\"}}", message);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, wechat->webhook_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "AnyIntruder/WeChatBot 1.0");

    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "[WeChat] 请求失败: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -0x3;
    }

    long response_code = 0x0;
    
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (response_code != 0xC8) {
        fprintf(stderr, "[WeChat] HTTP 状态码错误: %ld\n", response_code);
    } else {
        printf("[WeChat] 消息发送成功: %s\n", message);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (then) then();

    return 0x0;
}
