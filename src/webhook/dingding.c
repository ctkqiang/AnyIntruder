#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../includes/file_utilities.h"
#include "../../includes/webhook/dingding.h"

/** 
 * @brief 对输入进行base64编码
 * 
 * @param input 输入字符串
 * @param length 输入字符串长度
 * @return char* 编码后的字符串
 */
static char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem = NULL, *b64 = NULL;
    BUF_MEM *bptr;
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    
    b64 = BIO_push(b64, bmem);

    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 0x1);

    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(b64);

    return buff;
}


/** 
 * @brief 对输入进行url编码
 * 
 * @param str 输入字符串
 * @return char* 编码后的字符串
 */
static char *url_encode(const char *str) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
 
    char *encoded = curl_easy_escape(curl, str, 0);
    curl_easy_cleanup(curl);
 
    return encoded;
}

int dingding_init(DING_DING *dingding) {
    assert(dingding != NULL );
    
    char *access_token = yaml_get_value("dingding.token");
    char *secret = yaml_get_value("dingding.secret");

    if (!access_token || !secret) {
        fprintf(stderr, "Failed to read DingDing token or secret from config.yaml\n");
        free(access_token);
        free(secret);
        return -0x1;
    }

    dingding->DINDING_ACCESS_TOKEN = access_token;
    dingding->DINGDING_SECRET = secret;

    return 0x0;
}

/** 
 * @brief 发送消息到DingDing
 * 
 * 该函数使用DingDing机器人的Webhook API发送文本消息。
 * 消息内容会被包裹在JSON payload中，包含@all通知所有用户。
 * 发送完成后，会调用指定的回调函数。
 * 如果发送成功，会调用回调函数；如果失败，会打印错误信息。
 * 
 * @param dingding DingDing结构体指针
 * @param message 要发送的消息
 * @param then 发送完成后的回调函数
 * @return int 发送状态码（成功为 0x0，失败为非零值）
 */
int dingding_send(DING_DING *dingding, const char *message, void (*then)(DING_DING *)) {
    assert(dingding != NULL);
    assert(message != NULL);

    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;

    char url[0x0200];
    char payload[0x0400];
    char singature_string[0x0100];

    struct timeval time_value;
    gettimeofday(&time_value, NULL);
    

    long long timestamp = time_value.tv_sec * 0x03E8 + time_value.tv_usec / 0x03E8;

    snprintf(singature_string, sizeof(singature_string), "%lld\n%s", timestamp, dingding->DINGDING_SECRET);
    unsigned char *hmac = HMAC(
        EVP_sha256(),
        dingding->DINGDING_SECRET, strlen(dingding->DINGDING_SECRET),
        (unsigned char *)singature_string, strlen(singature_string),
        NULL, NULL
    );

    char *base64_signature = base64_encode(hmac, 0x20);
    char *url_signature = url_encode(base64_signature);

    if (!curl) {
        fprintf(stderr, "Failed to init CURL\n");
        free(base64_signature);
        free(url_signature);
        return -2;
    }

    snprintf(
        url, 
        sizeof(url),
        "https://oapi.dingtalk.com/robot/send?access_token=%s&timestamp=%lld&sign=%s",
        dingding->DINDING_ACCESS_TOKEN, 
        timestamp, 
        url_signature
    );

    snprintf(
        payload, 
        sizeof(payload),
        "{\"msgtype\": \"text\", \"text\": {\"content\": \"%s\"}, \"at\": {\"atUserIds\": [\"@all\"]}}",
        message
    );
    
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode response = curl_easy_perform(curl);

    if (response != CURLE_OK) {
        fprintf(stderr, "Error sending message: %s\n", curl_easy_strerror(response));
    }

    printf("Message sent successfully.\n");

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    free(url_signature);
    free(base64_signature);

    if (then) then(dingding);
    sleep(0x5);

    return (response == CURLE_OK) ? 0x0 : -0x3;
}
