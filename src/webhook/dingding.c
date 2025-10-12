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
